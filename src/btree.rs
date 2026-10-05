use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::database::{
    DatabaseError, EventDatabase, Index, IndexKey, ReadTransaction, Result, WriteTransaction,
    full_index_key,
};

// <prefix><inverted timestamp><short id> -> ()
type IndexMap = BTreeMap<Vec<u8>, ()>;

/// btree-based in-memory event database
///
/// there is no real transaction isolation here, writes are visible immediately.
#[derive(Clone, Default)]
pub struct BTreeEventDatabase {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    // main event storage: shortid -> archived event bytes
    events: RwLock<BTreeMap<u64, Arc<rkyv::util::AlignedVec>>>,

    // one map for each `Index`, in the order of `Index::ALL`
    indexes: [RwLock<IndexMap>; 6],
}

impl Inner {
    fn index(&self, index: &Index) -> &RwLock<IndexMap> {
        &self.indexes[*index as usize]
    }
}

impl BTreeEventDatabase {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventDatabase for BTreeEventDatabase {
    type ReadTxn = BTreeTransaction;
    type WriteTxn = BTreeTransaction;

    fn begin_read_txn(&self) -> Result<Self::ReadTxn> {
        Ok(BTreeTransaction {
            inner: self.inner.clone(),
        })
    }

    fn begin_write_txn(&self) -> Result<Self::WriteTxn> {
        Ok(BTreeTransaction {
            inner: self.inner.clone(),
        })
    }
}

#[derive(Clone)]
pub struct BTreeTransaction {
    inner: Arc<Inner>,
}

/// an archived event that stays alive (even if deleted from the database) while this is held
#[derive(Clone)]
pub struct BTreeEventRef(Arc<rkyv::util::AlignedVec>);

impl std::ops::Deref for BTreeEventRef {
    type Target = crate::ArchivedEvent;

    fn deref(&self) -> &Self::Target {
        // safety: these bytes were produced by rkyv::to_bytes::<Event>() in put_event() and are never
        // mutated afterwards
        unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(self.0.as_slice()) }
    }
}

impl ReadTransaction for BTreeTransaction {
    type EventRef = BTreeEventRef;

    fn has_event(&self, id: crate::ShortID) -> Result<bool> {
        Ok(self.inner.events.read().unwrap().contains_key(&id.0))
    }

    fn get_event(&self, id: crate::ShortID) -> Result<BTreeEventRef> {
        self.inner
            .events
            .read()
            .unwrap()
            .get(&id.0)
            .map(|bytes| BTreeEventRef(bytes.clone()))
            .ok_or(DatabaseError::EventNotFound)
    }

    fn scan_index(
        &self,
        index: &Index,
        from: std::ops::Bound<&[u8]>,
        cb: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<()> {
        let map = self.inner.index(index).read().unwrap();
        let from = from.map(|key| key.to_vec());
        for key in map
            .range((from, std::ops::Bound::Unbounded))
            .map(|(key, _)| key)
        {
            if !cb(key) {
                break;
            }
        }
        Ok(())
    }
}

impl WriteTransaction for BTreeTransaction {
    fn put_event(&mut self, event: &crate::Event) -> Result<()> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        self.inner
            .events
            .write()
            .unwrap()
            .insert(event.id.short().0, Arc::new(bytes));
        Ok(())
    }

    fn del_event(&mut self, id: crate::ShortID) -> Result<()> {
        self.inner.events.write().unwrap().remove(&id.0);
        Ok(())
    }

    fn put_key(&mut self, index_key: IndexKey) -> Result<()> {
        self.inner
            .index(&index_key.index)
            .write()
            .unwrap()
            .insert(full_index_key(&index_key), ());
        Ok(())
    }

    fn del_key(&mut self, index_key: IndexKey) -> Result<()> {
        self.inner
            .index(&index_key.index)
            .write()
            .unwrap()
            .remove(&full_index_key(&index_key));
        Ok(())
    }

    fn commit(self) -> Result<()> {
        // everything was already applied
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    crate::database::tests::database_test_suite!((crate::BTreeEventDatabase::new(), ()));
}
