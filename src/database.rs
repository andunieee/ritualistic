use std::hash::BuildHasher;

pub const TAG_HASHER_SEED: u64 = 64;

/// how many index entries a cursor reads at a time
const PULL_BATCH_SIZE: usize = 16;

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(thiserror::Error, Debug)]
pub enum DatabaseError {
    #[error("LMDB error: {0}")]
    Lmdb(String),

    #[error("redb error: {0}")]
    Redb(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] rkyv::rancor::Error),

    #[error("event with values out of expected boundaries {created_at}/{kind}")]
    OutOfBounds { created_at: i64, kind: u16 },

    #[error("duplicate event")]
    DuplicateEvent,

    #[error("event not found")]
    EventNotFound,

    #[error("invalid query: {0}")]
    InvalidFilter(String),
}

/// an event store with indexes, implemented on top of some ordered key-value store
///
/// all backends store the same things:
///   - events: <short id> -> <rkyv-archived event>
///   - one table per `Index`: <prefix><inverted big-endian timestamp><short id> -> <nothing>
///
/// so iterating an index in ascending order starting from <prefix><inverted until> yields events
/// from newest to oldest, which is what the query engine here needs.
pub trait EventDatabase {
    type ReadTxn: ReadTransaction;
    type WriteTxn: WriteTransaction;

    fn begin_read_txn(&self) -> Result<Self::ReadTxn>;
    fn begin_write_txn(&self) -> Result<Self::WriteTxn>;

    fn save_event(&self, event: &crate::Event) -> Result<()> {
        let mut txn = self.begin_write_txn()?;

        if txn.has_event(event.id.short())? {
            return Err(DatabaseError::DuplicateEvent);
        }

        txn.save(event)?;
        txn.commit()
    }

    fn delete_event(&self, id: crate::ShortID) -> Result<()> {
        let mut txn = self.begin_write_txn()?;
        txn.delete(id)?;
        txn.commit()
    }

    fn query_events(&self, filters: &mut [crate::Filter]) -> Result<QueryResults<Self::ReadTxn>> {
        let txn = self.begin_read_txn()?;
        let mut results = QueryResults::new(txn);

        for filter in filters {
            if filter.search.is_some() {
                log::warn!("ignoring query with search field");
                continue;
            }

            // id query, just process these ids and that's it
            if let Some(ids) = &filter.ids {
                results.ids.reserve(ids.len());
                for id in ids {
                    results.ids.push(id.short());
                }
            } else {
                plan_index_queries(&mut results.index_queries, filter);
            }
        }

        Ok(results)
    }

    /// save a replaceable or addressable event, deleting the older versions of it,
    /// unless there is already a newer one, in which case this does nothing
    fn replace_event(&self, event: &crate::Event, with_address: bool) -> Result<()> {
        let mut txn = self.begin_write_txn()?;

        // create filter to find existing events
        let mut filter = crate::Filter {
            kinds: Some(vec![event.kind]),
            authors: Some(vec![event.pubkey]),
            limit: Some(10),
            ..Default::default()
        };

        if with_address {
            filter.tags = Some(vec![crate::filter::TagQuery(
                "d".to_string(),
                vec![event.tags.get_d()],
            )]);
        }

        // find the existing versions first (some backends can't write while reading)
        let mut results = QueryResults::new(txn.clone());
        plan_index_queries(&mut results.index_queries, &mut filter);
        let existing: Vec<(u32, crate::ShortID)> = results
            .map(|existing| (existing.created_at.0.to_native(), existing.id.short()))
            .collect();

        if existing.iter().any(|(ts, _)| *ts >= event.created_at.0) {
            // a newer event (or this same one) already exists
            return Ok(());
        }

        for (_, id) in existing {
            txn.delete(id)?;
        }
        txn.save(event)?;
        txn.commit()
    }
}

pub trait ReadTransaction: Clone {
    /// a handle to an archived event that keeps it alive for as long as it is held
    type EventRef: std::ops::Deref<Target = crate::ArchivedEvent>;

    fn has_event(&self, id: crate::ShortID) -> Result<bool>;
    fn get_event(&self, id: crate::ShortID) -> Result<Self::EventRef>;

    /// calls `cb` with each key of the given index, in ascending order, starting from `from`,
    /// until there are no more keys or `cb` returns false
    fn scan_index(
        &self,
        index: &Index,
        from: std::ops::Bound<&[u8]>,
        cb: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<()>;
}

pub trait WriteTransaction: ReadTransaction {
    fn put_event(&mut self, event: &crate::Event) -> Result<()>;
    fn del_event(&mut self, id: crate::ShortID) -> Result<()>;
    fn put_key(&mut self, index_key: IndexKey) -> Result<()>;
    fn del_key(&mut self, index_key: IndexKey) -> Result<()>;

    /// persists everything done in this transaction, if this isn't called it is all discarded
    /// (except for the in-memory btree database, which doesn't have real transactions)
    fn commit(self) -> Result<()>;

    fn save(&mut self, event: &crate::Event) -> Result<()> {
        self.put_event(event)?;
        get_index_keys_for_event(event, |index_key| self.put_key(index_key))
    }

    fn delete(&mut self, id: crate::ShortID) -> Result<()> {
        // deserialize it fully before writing anything, as writes may invalidate the reference
        let event = match self.get_event(id) {
            Ok(event) => rkyv::deserialize::<crate::Event, rkyv::rancor::Error>(&*event)?,
            Err(DatabaseError::EventNotFound) => return Ok(()),
            Err(err) => return Err(err),
        };

        get_index_keys_for_event(&event, |index_key| self.del_key(index_key))?;
        self.del_event(id)
    }
}

/// the full key as stored in an index table: <key><short id>
pub fn full_index_key(index_key: &IndexKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(index_key.key.len() + 8);
    key.extend_from_slice(index_key.key);
    key.extend_from_slice(&index_key.id.0.to_ne_bytes());
    key
}

/// reads entries from one index for one `IndexQuery`, a batch at a time
struct IndexCursor {
    query: std::rc::Rc<IndexQuery>,
    pulled: std::collections::VecDeque<(u32, crate::ShortID)>,
    last_read_ts: u32,
    done: bool,
    last_key: Vec<u8>,
}

impl IndexCursor {
    fn new(query: std::rc::Rc<IndexQuery>) -> Self {
        Self {
            query,
            pulled: std::collections::VecDeque::with_capacity(PULL_BATCH_SIZE),
            last_read_ts: u32::MAX,
            done: false,
            last_key: Vec::new(),
        }
    }

    fn pull<T: ReadTransaction>(&mut self, txn: &T) {
        if self.done {
            return;
        }

        // the query key is <prefix><inverted until>, stored keys are <prefix><inverted ts><short id>
        let start_key = &self.query.key;
        let prefix_len = start_key.len() - 4;
        let end_ts = self.query.end_ts;

        let from = if self.last_key.is_empty() {
            std::ops::Bound::Included(start_key.as_slice())
        } else {
            std::ops::Bound::Excluded(self.last_key.as_slice())
        };

        let mut count = 0;
        let mut last_key = Vec::new();
        let pulled = &mut self.pulled;
        let last_read_ts = &mut self.last_read_ts;
        let result = txn.scan_index(&self.query.index, from, &mut |key| {
            if count == PULL_BATCH_SIZE
                || key.len() != prefix_len + 4 + 8
                || key[..prefix_len] != start_key[..prefix_len]
            {
                // either we have read enough for now or we've moved past the entries for this prefix
                return false;
            }

            let inverted_ts =
                u32::from_be_bytes(key[prefix_len..prefix_len + 4].try_into().unwrap());
            let ts = u32::MAX - inverted_ts;
            if ts < end_ts {
                return false;
            }

            let id = u64::from_ne_bytes(key[prefix_len + 4..].try_into().unwrap());
            pulled.push_back((ts, crate::ShortID(id)));
            *last_read_ts = ts;
            last_key.clear();
            last_key.extend_from_slice(key);
            count += 1;

            true
        });

        if let Err(err) = result {
            log::warn!("failed to read from index {:?}: {}", self.query.index, err);
            self.done = true;
        }

        if count < PULL_BATCH_SIZE {
            self.done = true;
        }
        if count > 0 {
            self.last_key = last_key;
        }
    }

    fn first_pulled_timestamp(&self) -> u32 {
        self.pulled.front().map(|(ts, _)| *ts).unwrap_or(0)
    }
}

pub struct QueryResults<T>
where
    T: ReadTransaction,
{
    txn: T,

    // ids are just fetched first and straightforwardly
    ids: Vec<crate::ShortID>,

    // index queries are more complex, they're fetched all at the same time and ordered dynamically
    index_queries: Vec<std::rc::Rc<IndexQuery>>,
    initialized: bool,         // whether the cursors have been initialized
    cursors: Vec<IndexCursor>, // in the beginning, one for each IndexQuery; these will be reordered many times.
    collectable: Vec<T::EventRef>,
    last_sent: Option<[u8; 32]>,
}

impl<T> QueryResults<T>
where
    T: ReadTransaction,
{
    fn new(txn: T) -> Self {
        Self {
            txn,
            ids: Vec::new(),
            index_queries: Vec::with_capacity(12),
            collectable: Vec::with_capacity(64),
            initialized: false,
            cursors: Vec::with_capacity(12),
            last_sent: None,
        }
    }
}

impl<T> Iterator for QueryResults<T>
where
    T: ReadTransaction,
{
    type Item = T::EventRef;

    fn next(&mut self) -> Option<Self::Item> {
        // first emit all ids
        while let Some(id) = self.ids.pop() {
            match self.txn.get_event(id) {
                Ok(event) => return Some(event),
                Err(DatabaseError::EventNotFound) => continue, // try the next
                Err(err) => {
                    log::warn!("get_event('{}') errored: {}", id, err);
                    return None;
                }
            }
        }

        // after those have ended start pulling results from the queries
        if self.index_queries.is_empty() {
            return None;
        }

        if !self.initialized {
            for query in self.index_queries.iter() {
                let mut cursor = IndexCursor::new(query.clone());

                // pull some entries from every cursor
                cursor.pull(&self.txn);

                self.cursors.push(cursor);
            }
            self.initialized = true;
        }

        loop {
            // dispatch next event to caller, filtering out duplicates
            while let Some(event) = self.collectable.pop() {
                if self.last_sent.replace(event.id.0) == Some(event.id.0) {
                    continue;
                }

                return Some(event);
            }

            // cleanup cursors that have ended and have nothing else to give us
            self.cursors.retain(|cursor| {
                let limit_reached = cursor
                    .query
                    .limit
                    .is_some_and(|limit| *cursor.query.total_sent.borrow() >= limit);
                !(cursor.done && (cursor.pulled.is_empty() || limit_reached))
            });

            if self.cursors.is_empty() {
                return None;
            }

            // sort such that the cursors that are the least advanced (i.e. that have read up to the
            // newest timestamp) will be at the end
            glidesort::sort_in_vec_by_key(&mut self.cursors, |c| c.last_read_ts);

            // any entry already pulled that has a timestamp higher than the least advanced cursor that
            // still has stuff to read can already be collected (cursors that are done don't hold
            // anything back, so if all are done we can collect everything)
            let cutpoint = self
                .cursors
                .iter()
                .rev()
                .find(|c| !c.done)
                .map(|c| c.last_read_ts)
                .unwrap_or(0);

            // reading from db and collecting events
            for cursor in &mut self.cursors {
                let query = cursor.query.clone();
                while !cursor.pulled.is_empty() {
                    if let Some(limit) = query.limit
                        && *query.total_sent.borrow() >= limit
                    {
                        cursor.done = true;
                        break;
                    }

                    // we'll always be collecting from the front
                    if cursor.first_pulled_timestamp() < cutpoint {
                        // from this point on we stop collecting
                        break;
                    }

                    // otherwise we're still good, collect this (and remove it)
                    let (_, id) = cursor.pulled.pop_front().unwrap();
                    let event = match self.txn.get_event(id) {
                        Err(err) => {
                            log::warn!("failed to get event with {}: {}", id, err);
                            continue;
                        }
                        Ok(event) => event,
                    };

                    // check if this event passes the other filters before actually sending it
                    if let Some(extra_kinds) = &query.extra_kinds
                        && !extra_kinds.contains(&event.kind.0)
                    {
                        continue;
                    };
                    if let Some(extra_authors) = &query.extra_authors
                        && !extra_authors.contains(&event.pubkey.0)
                    {
                        continue;
                    };
                    if let Some(extra_tag) = &query.extra_tag
                        && !event.tags.0.iter().any(|tag| {
                            tag.len() >= 2
                                && tag[0] == extra_tag.key()
                                && extra_tag.values().iter().any(|v| tag[1] == v.as_str())
                        })
                    {
                        continue;
                    }

                    // this event is ok
                    self.collectable.push(event);
                    *query.total_sent.borrow_mut() += 1;
                }
            }

            // after deciding what events are going to the client we order them (by id too so
            // duplicates coming from different index queries end up next to each other)
            self.collectable
                .sort_by_key(|event| (event.created_at.0.to_native(), event.id.0));

            // prepare the next round: pull more entries from the 4 least advanced cursors
            let mut pulled = 0;
            for cursor in self.cursors.iter_mut().rev() {
                if pulled == 4 {
                    break;
                }
                if !cursor.done {
                    cursor.pull(&self.txn);
                    pulled += 1;
                }
            }
        }
    }
}

pub struct IndexQuery {
    pub index: Index,
    pub key: Vec<u8>,

    // we'll scan each index up to this point (the last 4 bytes)
    pub end_ts: u32,

    // max number of results we'll return from this (if it specifies a limit)
    limit: Option<usize>,
    total_sent: std::rc::Rc<std::cell::RefCell<usize>>, // total for this filter, shared among all derived queries

    // these extra values will be matched against after we've read an event from the database
    extra_tag: Option<std::rc::Rc<crate::filter::TagQuery>>,
    extra_kinds: Option<std::rc::Rc<Vec<rkyv::Archived<u16>>>>,
    extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>>,
}

fn plan_index_queries(queries: &mut Vec<std::rc::Rc<IndexQuery>>, filter: &mut crate::Filter) {
    let crate::Filter {
        until,
        since,
        limit,
        authors: authors_,
        tags: tags_,
        kinds: kinds_,

        ids: _,
        search: _,
    } = filter;

    // must be encoded in the same way as in get_index_keys_for_event()
    let start_ts = until.map(|ts| ts.invert()).unwrap_or(0).to_be_bytes();
    let end_ts = since.map(|ts| ts.0).unwrap_or(0);
    let mut extra_tag: Option<std::rc::Rc<crate::filter::TagQuery>> = None;
    let mut second_best: Option<std::rc::Rc<crate::filter::TagQuery>> = None;

    let total_sent = std::rc::Rc::new(std::cell::RefCell::new(0));

    if let Some(mut tags) = tags_.take() {
        tags.sort_unstable_by_key(|tagq| tagq.worth());

        let best_tag = match tags.pop() {
            None => {
                // there must always be at least one tag if tags is present, so this is technically an error
                log::warn!("abort query with filter with Some([]) tags");
                return;
            }
            Some(tag) => tag,
        };

        if best_tag.worth() > 5 {
            // use tag query as the main index
            let second_best_tag = tags.pop().map(std::rc::Rc::new);

            plan_tag_queries(
                queries,
                &best_tag,
                &start_ts,
                end_ts,
                second_best_tag,
                kinds_.as_ref().map(|kinds| {
                    std::rc::Rc::new(
                        kinds
                            .iter()
                            .map(|kind| rkyv::Archived::<u16>::from_native(kind.0))
                            .collect(),
                    )
                }),
                authors_.as_ref().map(|authors| {
                    std::rc::Rc::new(authors.iter().map(|author| author.0).collect())
                }),
                *limit,
                total_sent,
            );

            return;
        }

        // if there is a "K" and a "p"/"P" use that special index
        {
            let mut k_values = Vec::new();
            let mut p_values = Vec::new();
            for tag in &tags {
                if tag.key() == "p" || tag.key() == "P" {
                    p_values.extend(tag.values());
                } else if tag.key() == "K" {
                    k_values.extend(tag.values());
                }
            }

            let mut used_this = false;
            let mut best_possible_tag: Option<std::rc::Rc<crate::TagQuery>> = None;
            let mut extra_kinds: Option<std::rc::Rc<Vec<rkyv::Archived<u16>>>> = None;
            let mut extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>> = None;

            for (k_value, p_value) in itertools::iproduct!(k_values, p_values) {
                let mut key = Vec::from([0u8; 8 + 2 + 4]);
                key[8 + 2..].copy_from_slice(&start_ts);

                if let Ok(k) = k_value.parse::<u16>() {
                    key[8..8 + 2].copy_from_slice(&k.to_ne_bytes());

                    if p_value.len() == 64
                        && lowercase_hex::decode_to_slice(
                            &p_value[8 * 2..8 * 2 + 8 * 2],
                            &mut key[0..8],
                        )
                        .is_ok()
                    {
                        if best_possible_tag.is_none() {
                            best_possible_tag = tags
                                .iter()
                                .find(|tag| {
                                    tag.key() != "p" && tag.key() != "P" && tag.key() != "K"
                                })
                                .map(|t| t.to_owned())
                                .map(std::rc::Rc::new);
                        }

                        if let Some(kinds) = kinds_.take() {
                            extra_kinds = Some(std::rc::Rc::new(
                                kinds
                                    .into_iter()
                                    .map(|kind| rkyv::Archived::<u16>::from_native(kind.0))
                                    .collect(),
                            ));
                        }

                        if let Some(authors) = authors_.take() {
                            extra_authors = Some(std::rc::Rc::new(
                                authors.into_iter().map(|author| author.0).collect(),
                            ));
                        }

                        queries.push(std::rc::Rc::new(IndexQuery {
                            index: Index::PtagKtag,
                            key,
                            end_ts,
                            extra_tag: best_possible_tag.clone(),
                            extra_kinds: extra_kinds.clone(),
                            extra_authors: extra_authors.clone(),
                            limit: *limit,
                            total_sent: total_sent.clone(),
                        }));

                        used_this = true;
                    }
                }
            }
            if used_this {
                return;
            }
        }

        // otherwise don't use a tag-based index
        // only use the first tag as the extra tag filter
        extra_tag = Some(std::rc::Rc::new(best_tag));

        // also keep the second best tag so we can use it maybe eventually
        second_best = tags.pop().map(std::rc::Rc::new);
    }

    if let (Some(authors), Some(kinds)) = (&authors_, &kinds_) {
        // kinds and authors
        // use pubkey-kind as the main index
        for author in authors {
            for kind in kinds {
                let mut key = Vec::from([0u8; 8 + 2 + 4]);
                key[8 + 2..].copy_from_slice(&start_ts);

                key[0..8].copy_from_slice(&author.short().0.to_ne_bytes());
                key[8..8 + 2].copy_from_slice(&kind.0.to_ne_bytes());

                queries.push(std::rc::Rc::new(IndexQuery {
                    index: Index::PubkeyKind,
                    key,
                    end_ts,
                    extra_tag: extra_tag.clone(),
                    extra_kinds: None,
                    extra_authors: None,

                    limit: *limit,
                    total_sent: total_sent.clone(),
                }));
            }
        }

        return;
    }

    if let Some(authors) = authors_.take() {
        // just authors
        for a in authors {
            let mut key = Vec::from([0u8; 8 + 4]);
            key[8..].copy_from_slice(&start_ts);
            key[0..8].copy_from_slice(&a.short().0.to_ne_bytes());

            queries.push(std::rc::Rc::new(IndexQuery {
                index: Index::Pubkey,
                key,
                end_ts,
                extra_tag: extra_tag.clone(),
                extra_kinds: None,
                extra_authors: None,

                limit: *limit,
                total_sent: total_sent.clone(),
            }));
        }

        return;
    }

    if let Some(kinds) = kinds_.take() {
        // just kinds
        for k in kinds {
            let mut key = Vec::from([0u8; 2 + 4]);
            key[2..].copy_from_slice(&start_ts);
            key[0..2].copy_from_slice(&k.0.to_ne_bytes());

            queries.push(std::rc::Rc::new(IndexQuery {
                index: Index::Kind,
                key,
                end_ts,
                extra_tag: extra_tag.clone(),
                extra_kinds: None,
                extra_authors: None,

                limit: *limit,
                total_sent: total_sent.clone(),
            }));
        }

        return;
    }

    // if we got here and we have an extra_tag, let's use that as our main query
    // as it's better than nothing
    if let Some(best_tagq) = &extra_tag {
        plan_tag_queries(
            queries,
            best_tagq,
            &start_ts,
            end_ts,
            second_best,
            None,
            None,
            *limit,
            total_sent,
        );
        return;
    }

    // no filters, use just the created_at index
    queries.push(std::rc::Rc::new(IndexQuery {
        index: Index::Timestamp,
        key: start_ts.into(),
        end_ts,
        extra_tag: None,
        extra_kinds: None,
        extra_authors: None,

        limit: *limit,
        total_sent,
    }));
}

#[allow(clippy::too_many_arguments)]
fn plan_tag_queries(
    queries: &mut Vec<std::rc::Rc<IndexQuery>>,
    tq: &crate::TagQuery,
    start_ts: &[u8],
    end_ts: u32,
    extra_tag: Option<std::rc::Rc<crate::TagQuery>>,
    extra_kinds: Option<std::rc::Rc<Vec<rkyv::Archived<u16>>>>,
    extra_authors: Option<std::rc::Rc<Vec<[u8; 32]>>>,
    limit: Option<usize>,
    total_sent: std::rc::Rc<std::cell::RefCell<usize>>,
) {
    for v in &tq.1 {
        let mut key = [0u8; 1 + 8 + 4];
        key[1 + 8..].copy_from_slice(start_ts);

        if !tq.0.is_empty() {
            key[0] = tq.0.as_bytes()[0];
        }

        // must be encoded in the same way as in get_index_keys_for_event()
        if !(v.len() == 64
            && lowercase_hex::decode_to_slice(&v[8 * 2..8 * 2 + 8 * 2], &mut key[1..1 + 8]).is_ok())
        {
            let hash = foldhash::fast::FixedState::with_seed(TAG_HASHER_SEED).hash_one(v);
            key[1..1 + 8].copy_from_slice(&hash.to_ne_bytes());
        }
        let key = Vec::from(&key[..]);

        queries.push(std::rc::Rc::new(IndexQuery {
            index: Index::Tag,
            key,

            end_ts,
            extra_tag: extra_tag.clone(),
            extra_kinds: extra_kinds.clone(),
            extra_authors: extra_authors.clone(),

            limit,
            total_sent: total_sent.clone(),
        }));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Index {
    Timestamp,
    Pubkey,
    PubkeyKind,
    Kind,
    Tag,
    PtagKtag,
}

impl Index {
    pub const ALL: [Index; 6] = [
        Index::Timestamp,
        Index::Pubkey,
        Index::PubkeyKind,
        Index::Kind,
        Index::Tag,
        Index::PtagKtag,
    ];

    /// the name of the table/database where this index is stored
    pub const fn name(&self) -> &'static str {
        match self {
            Index::Timestamp => "timestamp",
            Index::Pubkey => "pubkey",
            Index::PubkeyKind => "pubkey_kind",
            Index::Kind => "kind",
            Index::Tag => "tag",
            Index::PtagKtag => "ptag_ktag",
        }
    }
}

#[derive(Debug)]
pub struct IndexKey<'a> {
    pub index: Index,
    pub key: &'a [u8],
    pub id: crate::ShortID,
}

fn get_index_keys_for_event<F>(event: &crate::Event, mut cb: F) -> crate::database::Result<()>
where
    F: FnMut(IndexKey) -> crate::database::Result<()>,
{
    // this is so the events are ordered from newer to older
    let ts_bytes = &event.created_at.invert().to_be_bytes();
    let id = event.id.short();

    // by date only
    {
        cb(IndexKey {
            index: Index::Timestamp,
            key: ts_bytes,
            id,
        })?;
    }

    // by kind + date
    {
        let mut key = [0u8; 2 + 4];
        key[0..2].copy_from_slice(&event.kind.0.to_ne_bytes());
        key[2..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::Kind,
            key: &key,
            id,
        })?;
    }

    // by pubkey + date
    {
        let mut key = [0u8; 8 + 4];
        key[0..8].copy_from_slice(&event.pubkey.short().0.to_ne_bytes());
        key[8..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::Pubkey,
            key: &key,
            id,
        })?;
    }

    // by pubkey + kind + date
    {
        let mut key = [0u8; 8 + 2 + 4];
        key[0..8].copy_from_slice(&event.pubkey.short().0.to_ne_bytes());
        key[8..8 + 2].copy_from_slice(&event.kind.0.to_ne_bytes());
        key[8 + 2..].copy_from_slice(ts_bytes);
        cb(IndexKey {
            index: Index::PubkeyKind,
            key: &key,
            id,
        })?;
    }

    // by tag value + date
    let mut tag_key: Option<[u8; 1 + 8 + 4]> = None;
    for tag in &event.tags.0 {
        if tag.len() < 2 || tag[0].len() != 1 {
            continue;
        }

        let key = tag_key.get_or_insert_with(|| {
            let mut key = [0u8; 1 + 8 + 4];
            key[1 + 8..].copy_from_slice(ts_bytes);
            key
        });
        key[0] = tag[0].as_bytes()[0];

        if tag[1].len() == 64
            && lowercase_hex::decode_to_slice(&tag[1][8 * 2..8 * 2 + 8 * 2], &mut key[1..1 + 8])
                .is_ok()
        {
            cb(IndexKey {
                index: Index::Tag,
                key,
                id,
            })?;
            continue;
        }

        let hash = foldhash::fast::FixedState::with_seed(TAG_HASHER_SEED).hash_one(&tag[1]);
        key[1..1 + 8].copy_from_slice(hash.to_ne_bytes().as_slice());

        cb(IndexKey {
            index: Index::Tag,
            key,
            id,
        })?;
    }

    // by p-tag + k-tag (includes all variantions possible)
    let mut kp_key: Option<[u8; 8 + 2 + 4]> = None;
    for (k_tagname, p_tagname) in [("K", "p"), ("K", "P")] {
        for k_tag in &event.tags.0 {
            if k_tag.len() >= 2 && k_tag[0] == k_tagname {
                if let Ok(k) = k_tag[1].parse::<u16>() {
                    let key = kp_key.get_or_insert_with(|| {
                        let mut key = [0u8; 8 + 2 + 4];
                        key[8 + 2..].copy_from_slice(ts_bytes); // prefill date for all
                        key
                    });

                    key[8..8 + 2].copy_from_slice(&k.to_ne_bytes()); // prefill "k" for these

                    for p_tag in &event.tags.0 {
                        if p_tag.len() >= 2
                            && p_tag[0] == p_tagname
                            && p_tag[1].len() == 64
                            && lowercase_hex::decode_to_slice(
                                &p_tag[1][8 * 2..8 * 2 + 8 * 2],
                                &mut key[0..8],
                            )
                            .is_ok()
                        {
                            cb(IndexKey {
                                index: Index::PtagKtag,
                                key,
                                id,
                            })?;
                        }
                    }
                }

                // only do one k-tag per event
                break;
            }
        }
    }

    Ok(())
}

/// tests that every `EventDatabase` implementation must pass
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{Event, Filter, ID, Kind, Signature, TagQuery, Tags, Timestamp};

    pub const PK1: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    pub const PK2: &str = "d91191e30e00444b942c0e82cad470b32af171764c2275bee0bd99377efd4075";
    const ETAG: &str = "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5";

    /// generates one #[test] for each test in this module, using `$make_db` to get a fresh database
    /// (as a tuple with something that must be kept alive while it's used, like a temporary directory)
    macro_rules! database_test_suite {
        ($make_db:expr) => {
            crate::database::tests::database_test_suite!(@tests $make_db;
                basic_operations,
                order_and_same_timestamp,
                limit_since_until,
                authors_kinds_tags,
                ids,
                many_events_across_batches,
                replace_and_delete,
                replace_addressable,
                event_ref_outlives_delete,
            );
        };
        (@tests $make_db:expr; $($name:ident),* $(,)?) => {
            $(
                #[test]
                fn $name() {
                    let (db, _guard) = $make_db;
                    crate::database::tests::$name(&db);
                }
            )*
        };
    }
    pub(crate) use database_test_suite;

    /// an event whose id starts with `n` (and whose short id is derived from `n` too)
    pub fn event(n: u8, pubkey: &str, kind: u16, ts: u32, tags: Vec<Vec<&str>>) -> Event {
        let mut id = [0u8; 32];
        id[0] = n;
        id[8] = n;
        Event {
            id: ID::from_bytes(id),
            pubkey: pubkey.parse().unwrap(),
            created_at: Timestamp(ts),
            kind: Kind(kind),
            tags: Tags(
                tags.into_iter()
                    .map(|t| t.into_iter().map(String::from).collect())
                    .collect(),
            ),
            content: format!("event {}", n),
            sig: Signature::from_bytes([0u8; 64]),
        }
    }

    /// the first byte of the id of each result
    pub fn query(db: &impl EventDatabase, filter: Filter) -> Vec<u8> {
        db.query_events(&mut [filter])
            .unwrap()
            .map(|e| e.id.0[0])
            .collect()
    }

    fn fill(db: &impl EventDatabase) {
        for evt in [
            event(1, PK1, 1, 100, vec![]),
            event(2, PK1, 1, 200, vec![vec!["e", ETAG]]),
            event(3, PK2, 1, 300, vec![vec!["t", "nostr"]]),
            event(4, PK2, 1, 300, vec![vec!["e", ETAG], vec!["t", "nostr"]]),
            event(5, PK1, 7, 250, vec![vec!["e", ETAG]]),
            event(6, PK2, 0, 50, vec![]),
        ] {
            db.save_event(&evt).unwrap();
        }
    }

    fn kinds(kinds: &[u16]) -> Filter {
        Filter {
            kinds: Some(kinds.iter().map(|k| Kind(*k)).collect()),
            ..Default::default()
        }
    }

    pub fn basic_operations(db: &impl EventDatabase) {
        let evt = event(1, PK1, 1, 1234567890, vec![]);
        db.save_event(&evt).unwrap();

        let retrieved = db
            .query_events(&mut [Filter::default()])
            .unwrap()
            .next()
            .unwrap();
        assert_eq!(evt.id, retrieved.id);
        assert_eq!(retrieved.content.as_str(), "event 1");
        assert!(
            db.begin_read_txn()
                .unwrap()
                .has_event(evt.id.short())
                .unwrap()
        );

        assert!(matches!(
            db.save_event(&evt),
            Err(DatabaseError::DuplicateEvent)
        ));

        db.delete_event(evt.id.short()).unwrap();
        assert!(
            !db.begin_read_txn()
                .unwrap()
                .has_event(evt.id.short())
                .unwrap()
        );
        assert_eq!(query(db, Filter::default()), Vec::<u8>::new());

        // deleting something that doesn't exist is fine
        db.delete_event(evt.id.short()).unwrap();
    }

    pub fn order_and_same_timestamp(db: &impl EventDatabase) {
        fill(db);
        assert_eq!(query(db, Filter::default()), vec![4, 3, 5, 2, 1, 6]);
        assert_eq!(query(db, kinds(&[1])), vec![4, 3, 2, 1]);
    }

    pub fn limit_since_until(db: &impl EventDatabase) {
        fill(db);
        assert_eq!(
            query(
                db,
                Filter {
                    limit: Some(3),
                    ..kinds(&[1])
                }
            ),
            vec![4, 3, 2]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    since: Some(Timestamp(150)),
                    ..kinds(&[1])
                }
            ),
            vec![4, 3, 2]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    until: Some(Timestamp(250)),
                    ..kinds(&[1])
                }
            ),
            vec![2, 1]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    since: Some(Timestamp(200)),
                    until: Some(Timestamp(250)),
                    ..Default::default()
                }
            ),
            vec![5, 2]
        );
    }

    pub fn authors_kinds_tags(db: &impl EventDatabase) {
        fill(db);
        let pk1 = PK1.parse().unwrap();
        let pk2 = PK2.parse().unwrap();

        assert_eq!(
            query(
                db,
                Filter {
                    authors: Some(vec![pk1]),
                    ..Default::default()
                }
            ),
            vec![5, 2, 1]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    authors: Some(vec![pk1, pk2]),
                    ..kinds(&[1])
                }
            ),
            vec![4, 3, 2, 1]
        );
        assert_eq!(query(db, kinds(&[1, 7])), vec![4, 3, 5, 2, 1]);
        assert_eq!(
            query(
                db,
                Filter {
                    tags: Some(vec![TagQuery("e".to_string(), vec![ETAG.to_string()])]),
                    ..Default::default()
                }
            ),
            vec![4, 5, 2]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    tags: Some(vec![TagQuery("t".to_string(), vec!["nostr".to_string()])]),
                    ..kinds(&[1])
                }
            ),
            vec![4, 3]
        );
        assert_eq!(
            query(
                db,
                Filter {
                    tags: Some(vec![TagQuery("t".to_string(), vec!["other".to_string()])]),
                    ..Default::default()
                }
            ),
            Vec::<u8>::new()
        );
    }

    pub fn ids(db: &impl EventDatabase) {
        fill(db);
        let mut got = query(
            db,
            Filter {
                ids: Some(vec![
                    event(2, PK1, 0, 0, vec![]).id,
                    event(5, PK1, 0, 0, vec![]).id,
                    event(99, PK1, 0, 0, vec![]).id,
                ]),
                ..Default::default()
            },
        );
        got.sort();
        assert_eq!(got, vec![2, 5]);
    }

    pub fn many_events_across_batches(db: &impl EventDatabase) {
        for i in 0..100u8 {
            let pk = if i % 2 == 0 { PK1 } else { PK2 };
            db.save_event(&event(i, pk, 1, 1000 + i as u32, vec![]))
                .unwrap();
        }

        let both = Filter {
            authors: Some(vec![PK1.parse().unwrap(), PK2.parse().unwrap()]),
            ..Default::default()
        };
        assert_eq!(
            query(db, both.clone()),
            (0..100u8).rev().collect::<Vec<_>>()
        );
        assert_eq!(
            query(
                db,
                Filter {
                    limit: Some(30),
                    ..both
                }
            ),
            (70..100u8).rev().collect::<Vec<_>>()
        );
    }

    pub fn replace_and_delete(db: &impl EventDatabase) {
        fill(db);
        let profile = Filter {
            authors: Some(vec![PK2.parse().unwrap()]),
            ..kinds(&[0])
        };

        db.replace_event(&event(7, PK2, 0, 60, vec![]), false)
            .unwrap();
        assert_eq!(query(db, profile.clone()), vec![7]);

        // older, ignored
        db.replace_event(&event(8, PK2, 0, 40, vec![]), false)
            .unwrap();
        assert_eq!(query(db, profile.clone()), vec![7]);

        db.delete_event(event(4, PK2, 1, 300, vec![]).id.short())
            .unwrap();
        assert_eq!(query(db, kinds(&[1])), vec![3, 2, 1]);
    }

    pub fn replace_addressable(db: &impl EventDatabase) {
        db.replace_event(&event(1, PK1, 30023, 10, vec![vec!["d", "a"]]), true)
            .unwrap();
        db.replace_event(&event(2, PK1, 30023, 10, vec![vec!["d", "b"]]), true)
            .unwrap();
        db.replace_event(&event(3, PK1, 30023, 20, vec![vec!["d", "a"]]), true)
            .unwrap();
        assert_eq!(query(db, kinds(&[30023])), vec![3, 2]);
    }

    pub fn event_ref_outlives_delete(db: &impl EventDatabase) {
        let evt = event(3, PK1, 1, 10, vec![]);
        db.save_event(&evt).unwrap();

        let txn = db.begin_read_txn().unwrap();
        let held = txn.get_event(evt.id.short()).unwrap();
        db.delete_event(evt.id.short()).unwrap();

        assert!(
            !db.begin_read_txn()
                .unwrap()
                .has_event(evt.id.short())
                .unwrap()
        );
        assert_eq!(held.content.as_str(), "event 3");
    }
}
