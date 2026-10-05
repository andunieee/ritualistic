use std::rc::Rc;

use redb::{ReadableDatabase, ReadableTable};

use crate::database::{
    DatabaseError, EventDatabase, Index, IndexKey, ReadTransaction, Result, WriteTransaction,
    full_index_key,
};

type EventsTable = redb::TableDefinition<'static, u64, &'static [u8]>;
type IndexTable = redb::TableDefinition<'static, &'static [u8], ()>;

const EVENTS: EventsTable = redb::TableDefinition::new("events");
const INDEXES: [IndexTable; 6] = [
    redb::TableDefinition::new(Index::Timestamp.name()),
    redb::TableDefinition::new(Index::Pubkey.name()),
    redb::TableDefinition::new(Index::PubkeyKind.name()),
    redb::TableDefinition::new(Index::Kind.name()),
    redb::TableDefinition::new(Index::Tag.name()),
    redb::TableDefinition::new(Index::PtagKtag.name()),
];

fn index_table(index: &Index) -> IndexTable {
    INDEXES[*index as usize]
}

/// redb-based persistent event database
///
/// events are copied out of the database when read.
#[derive(Clone)]
pub struct RedbEventDatabase {
    db: std::sync::Arc<redb::Database>,
}

impl RedbEventDatabase {
    /// open (or create) a database at the given file
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let db = redb::Database::create(path).map_err(err)?;

        // create all tables upfront, as read transactions can't open tables that don't exist
        let txn = db.begin_write().map_err(err)?;
        txn.open_table(EVENTS).map_err(err)?;
        for table in INDEXES {
            txn.open_table(table).map_err(err)?;
        }
        txn.commit().map_err(err)?;

        Ok(Self {
            db: std::sync::Arc::new(db),
        })
    }
}

impl EventDatabase for RedbEventDatabase {
    type ReadTxn = RedbTransaction;
    type WriteTxn = RedbTransaction;

    fn begin_read_txn(&self) -> Result<Self::ReadTxn> {
        Ok(RedbTransaction(Txn::Read(Rc::new(
            self.db.begin_read().map_err(err)?,
        ))))
    }

    fn begin_write_txn(&self) -> Result<Self::WriteTxn> {
        Ok(RedbTransaction(Txn::Write(Rc::new(
            self.db.begin_write().map_err(err)?,
        ))))
    }
}

#[derive(Clone)]
pub struct RedbTransaction(Txn);

#[derive(Clone)]
enum Txn {
    Read(Rc<redb::ReadTransaction>),
    Write(Rc<redb::WriteTransaction>),
}

/// an archived event copied out of the database
pub struct RedbEventRef(rkyv::util::AlignedVec);

impl std::ops::Deref for RedbEventRef {
    type Target = crate::ArchivedEvent;

    fn deref(&self) -> &Self::Target {
        // safety: these bytes were produced by rkyv::to_bytes::<Event>() in put_event()
        unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(self.0.as_slice()) }
    }
}

// tables opened from read and write transactions have different types, but both are ReadableTable,
// so this runs the same code with either
macro_rules! with_table {
    ($txn:expr, $def:expr, |$table:ident| $body:expr) => {
        match &$txn.0 {
            Txn::Read(txn) => {
                let $table = txn.open_table($def).map_err(err)?;
                $body
            }
            Txn::Write(txn) => {
                let $table = txn.open_table($def).map_err(err)?;
                $body
            }
        }
    };
}

impl RedbTransaction {
    fn write(&self) -> Result<&redb::WriteTransaction> {
        match &self.0 {
            Txn::Write(txn) => Ok(txn),
            Txn::Read(_) => Err(DatabaseError::Redb(
                "can't write in a read transaction".to_string(),
            )),
        }
    }
}

impl ReadTransaction for RedbTransaction {
    type EventRef = RedbEventRef;

    fn has_event(&self, id: crate::ShortID) -> Result<bool> {
        with_table!(self, EVENTS, |table| Ok(table
            .get(id.0)
            .map_err(err)?
            .is_some()))
    }

    fn get_event(&self, id: crate::ShortID) -> Result<RedbEventRef> {
        with_table!(self, EVENTS, |table| {
            let guard = table
                .get(id.0)
                .map_err(err)?
                .ok_or(DatabaseError::EventNotFound)?;
            let bytes = guard.value();
            let mut owned = rkyv::util::AlignedVec::with_capacity(bytes.len());
            owned.extend_from_slice(bytes);
            Ok(RedbEventRef(owned))
        })
    }

    fn scan_index(
        &self,
        index: &Index,
        from: std::ops::Bound<&[u8]>,
        cb: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<()> {
        with_table!(self, index_table(index), |table| {
            for entry in table
                .range::<&[u8]>((from, std::ops::Bound::Unbounded))
                .map_err(err)?
            {
                let (key, _) = entry.map_err(err)?;
                if !cb(key.value()) {
                    break;
                }
            }
            Ok(())
        })
    }
}

impl WriteTransaction for RedbTransaction {
    fn put_event(&mut self, event: &crate::Event) -> Result<()> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        let mut table = self.write()?.open_table(EVENTS).map_err(err)?;
        table
            .insert(event.id.short().0, bytes.as_slice())
            .map_err(err)?;
        Ok(())
    }

    fn del_event(&mut self, id: crate::ShortID) -> Result<()> {
        let mut table = self.write()?.open_table(EVENTS).map_err(err)?;
        table.remove(id.0).map_err(err)?;
        Ok(())
    }

    fn put_key(&mut self, index_key: IndexKey) -> Result<()> {
        let mut table = self
            .write()?
            .open_table(index_table(&index_key.index))
            .map_err(err)?;
        table
            .insert(full_index_key(&index_key).as_slice(), ())
            .map_err(err)?;
        Ok(())
    }

    fn del_key(&mut self, index_key: IndexKey) -> Result<()> {
        let mut table = self
            .write()?
            .open_table(index_table(&index_key.index))
            .map_err(err)?;
        table
            .remove(full_index_key(&index_key).as_slice())
            .map_err(err)?;
        Ok(())
    }

    fn commit(self) -> Result<()> {
        match self.0 {
            Txn::Write(txn) => Rc::try_unwrap(txn)
                .map_err(|_| {
                    DatabaseError::Redb(
                        "can't commit a transaction that is still in use".to_string(),
                    )
                })?
                .commit()
                .map_err(err),
            Txn::Read(_) => Ok(()),
        }
    }
}

fn err(err: impl Into<redb::Error>) -> DatabaseError {
    DatabaseError::Redb(err.into().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::tests::{PK1, event, query};

    fn temp_db() -> (RedbEventDatabase, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            RedbEventDatabase::open(dir.path().join("db.redb")).unwrap(),
            dir,
        )
    }

    mod suite {
        crate::database::tests::database_test_suite!(super::temp_db());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.redb");
        {
            let db = RedbEventDatabase::open(&path).unwrap();
            db.save_event(&event(1, PK1, 1, 10, vec![])).unwrap();
            db.save_event(&event(2, PK1, 1, 20, vec![])).unwrap();
        }

        let db = RedbEventDatabase::open(&path).unwrap();
        assert_eq!(query(&db, crate::Filter::default()), vec![2, 1]);
    }

    #[test]
    fn uncommitted_writes_are_discarded() {
        let (db, _dir) = temp_db();
        {
            let mut txn = db.begin_write_txn().unwrap();
            txn.save(&event(1, PK1, 1, 10, vec![])).unwrap();
            // dropped without commit
        }
        assert_eq!(query(&db, crate::Filter::default()), Vec::<u8>::new());
    }
}
