use std::rc::Rc;
use std::sync::Arc;

use lmdb_master_sys as ffi;

use crate::database::{
    DatabaseError, EventDatabase, Index, IndexKey, ReadTransaction, Result, WriteTransaction,
    full_index_key,
};

/// default maximum size of the database (this is just reserved address space, not disk usage)
pub const DEFAULT_MAP_SIZE: usize = 1 << 34;

/// LMDB-based persistent event database
///
/// events read in read transactions are accessed directly from the memory map, without copying.
#[derive(Clone)]
pub struct LMDBEventDatabase {
    env: Arc<Env>,
}

struct Env {
    env: *mut ffi::MDB_env,
    events: ffi::MDB_dbi,
    // one for each `Index`, in the order of `Index::ALL`
    indexes: [ffi::MDB_dbi; 6],
}

// safety: the environment is thread-safe and opened with MDB_NOTLS so read transactions aren't
// tied to threads; transactions themselves are not Send (they're behind an Rc)
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

impl Drop for Env {
    fn drop(&mut self) {
        unsafe { ffi::mdb_env_close(self.env) };
    }
}

impl LMDBEventDatabase {
    /// open (or create) a database at the given directory
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::open_with_map_size(path, DEFAULT_MAP_SIZE)
    }

    pub fn open_with_map_size(path: impl AsRef<std::path::Path>, map_size: usize) -> Result<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;
        let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| DatabaseError::Lmdb("path contains a null byte".to_string()))?;

        unsafe {
            let mut env: *mut ffi::MDB_env = std::ptr::null_mut();
            check(ffi::mdb_env_create(&mut env))?;

            // from here on the env must be closed if something fails
            let setup = || -> Result<Env> {
                check(ffi::mdb_env_set_maxdbs(env, 1 + Index::ALL.len() as u32))?;
                check(ffi::mdb_env_set_maxreaders(env, 1000))?;
                check(ffi::mdb_env_set_mapsize(env, map_size as _))?;
                check(ffi::mdb_env_open(
                    env,
                    c_path.as_ptr(),
                    ffi::MDB_NOTLS,
                    0o644,
                ))?;

                let mut txn: *mut ffi::MDB_txn = std::ptr::null_mut();
                check(ffi::mdb_txn_begin(env, std::ptr::null_mut(), 0, &mut txn))?;
                let open = |name: &str| -> Result<ffi::MDB_dbi> {
                    let c_name = std::ffi::CString::new(name).unwrap();
                    let mut dbi: ffi::MDB_dbi = 0;
                    check(ffi::mdb_dbi_open(
                        txn,
                        c_name.as_ptr(),
                        ffi::MDB_CREATE,
                        &mut dbi,
                    ))?;
                    Ok(dbi)
                };

                let dbis = (|| -> Result<_> {
                    let events = open("events")?;
                    let mut indexes = [0; 6];
                    for index in Index::ALL {
                        indexes[index as usize] = open(index.name())?;
                    }
                    Ok((events, indexes))
                })();

                match dbis {
                    Ok((events, indexes)) => {
                        check(ffi::mdb_txn_commit(txn))?;
                        Ok(Env {
                            env,
                            events,
                            indexes,
                        })
                    }
                    Err(err) => {
                        ffi::mdb_txn_abort(txn);
                        Err(err)
                    }
                }
            };

            match setup() {
                Ok(env) => Ok(Self { env: Arc::new(env) }),
                Err(err) => {
                    ffi::mdb_env_close(env);
                    Err(err)
                }
            }
        }
    }

    fn begin(&self, read_only: bool) -> Result<LMDBTransaction> {
        let mut txn: *mut ffi::MDB_txn = std::ptr::null_mut();
        let flags = if read_only { ffi::MDB_RDONLY } else { 0 };
        check(unsafe { ffi::mdb_txn_begin(self.env.env, std::ptr::null_mut(), flags, &mut txn) })?;

        Ok(LMDBTransaction {
            inner: Rc::new(Txn {
                txn,
                read_only,
                committed: std::cell::Cell::new(false),
                env: self.env.clone(),
            }),
        })
    }
}

impl EventDatabase for LMDBEventDatabase {
    type ReadTxn = LMDBTransaction;
    type WriteTxn = LMDBTransaction;

    fn begin_read_txn(&self) -> Result<Self::ReadTxn> {
        self.begin(true)
    }

    fn begin_write_txn(&self) -> Result<Self::WriteTxn> {
        self.begin(false)
    }
}

struct Txn {
    txn: *mut ffi::MDB_txn,
    read_only: bool,
    committed: std::cell::Cell<bool>,
    // declared last so the environment is only closed after the transaction is aborted
    env: Arc<Env>,
}

impl Drop for Txn {
    fn drop(&mut self) {
        // mdb_txn_commit() frees the handle (even when it fails), otherwise we must abort it
        if !self.committed.get() {
            unsafe { ffi::mdb_txn_abort(self.txn) };
        }
    }
}

#[derive(Clone)]
pub struct LMDBTransaction {
    inner: Rc<Txn>,
}

/// an archived event, either pointing straight into the memory map (in read transactions, where the
/// data is guaranteed to stay valid until the transaction ends, which this keeps alive) or copied
/// (in write transactions, where further writes could invalidate the pointer)
pub struct LMDBEventRef(EventBytes);

enum EventBytes {
    Mapped {
        _txn: Rc<Txn>,
        ptr: *const u8,
        len: usize,
    },
    Owned(rkyv::util::AlignedVec),
}

impl std::ops::Deref for LMDBEventRef {
    type Target = crate::ArchivedEvent;

    fn deref(&self) -> &Self::Target {
        let bytes = match &self.0 {
            EventBytes::Mapped { ptr, len, .. } => unsafe {
                std::slice::from_raw_parts(*ptr, *len)
            },
            EventBytes::Owned(bytes) => bytes.as_slice(),
        };

        // safety: these bytes were produced by rkyv::to_bytes::<Event>() in put_event() and archived
        // types have no alignment requirements (we use rkyv's "unaligned" feature)
        unsafe { rkyv::access_unchecked::<crate::ArchivedEvent>(bytes) }
    }
}

impl LMDBTransaction {
    fn index_dbi(&self, index: &Index) -> ffi::MDB_dbi {
        self.inner.env.indexes[*index as usize]
    }

    fn get_raw(&self, id: crate::ShortID) -> Result<Option<&[u8]>> {
        let id_bytes = id.0.to_ne_bytes();
        let mut key = val(&id_bytes);
        let mut data = val(&[]);
        let rc =
            unsafe { ffi::mdb_get(self.inner.txn, self.inner.env.events, &mut key, &mut data) };
        if rc == ffi::MDB_NOTFOUND {
            return Ok(None);
        }
        check(rc)?;
        Ok(Some(unsafe { slice(&data) }))
    }

    fn put(&mut self, dbi: ffi::MDB_dbi, key: &[u8], data: &[u8]) -> Result<()> {
        let mut key = val(key);
        let mut data = val(data);
        check(unsafe { ffi::mdb_put(self.inner.txn, dbi, &mut key, &mut data, 0) })
    }

    fn del(&mut self, dbi: ffi::MDB_dbi, key: &[u8]) -> Result<()> {
        let mut key = val(key);
        let rc = unsafe { ffi::mdb_del(self.inner.txn, dbi, &mut key, std::ptr::null_mut()) };
        if rc == ffi::MDB_NOTFOUND {
            return Ok(());
        }
        check(rc)
    }
}

impl ReadTransaction for LMDBTransaction {
    type EventRef = LMDBEventRef;

    fn has_event(&self, id: crate::ShortID) -> Result<bool> {
        Ok(self.get_raw(id)?.is_some())
    }

    fn get_event(&self, id: crate::ShortID) -> Result<LMDBEventRef> {
        let bytes = self.get_raw(id)?.ok_or(DatabaseError::EventNotFound)?;

        if self.inner.read_only {
            Ok(LMDBEventRef(EventBytes::Mapped {
                _txn: self.inner.clone(),
                ptr: bytes.as_ptr(),
                len: bytes.len(),
            }))
        } else {
            let mut owned = rkyv::util::AlignedVec::with_capacity(bytes.len());
            owned.extend_from_slice(bytes);
            Ok(LMDBEventRef(EventBytes::Owned(owned)))
        }
    }

    fn scan_index(
        &self,
        index: &Index,
        from: std::ops::Bound<&[u8]>,
        cb: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<()> {
        let mut cursor: *mut ffi::MDB_cursor = std::ptr::null_mut();
        check(unsafe { ffi::mdb_cursor_open(self.inner.txn, self.index_dbi(index), &mut cursor) })?;
        let _guard = CursorGuard(cursor);

        let (start, op, exclude) = match from {
            std::ops::Bound::Included(start) => (start, ffi::MDB_SET_RANGE, None),
            std::ops::Bound::Excluded(start) => (start, ffi::MDB_SET_RANGE, Some(start)),
            std::ops::Bound::Unbounded => (&[][..], ffi::MDB_FIRST, None),
        };
        let mut key = val(start);
        let mut data = val(&[]);

        let mut rc = unsafe { ffi::mdb_cursor_get(cursor, &mut key, &mut data, op) };
        loop {
            if rc == ffi::MDB_NOTFOUND {
                return Ok(());
            }
            check(rc)?;

            let current = unsafe { slice(&key) };
            if exclude != Some(current) && !cb(current) {
                return Ok(());
            }

            rc = unsafe { ffi::mdb_cursor_get(cursor, &mut key, &mut data, ffi::MDB_NEXT) };
        }
    }
}

impl WriteTransaction for LMDBTransaction {
    fn put_event(&mut self, event: &crate::Event) -> Result<()> {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        let events = self.inner.env.events;
        self.put(events, &event.id.short().0.to_ne_bytes(), &bytes)
    }

    fn del_event(&mut self, id: crate::ShortID) -> Result<()> {
        let events = self.inner.env.events;
        self.del(events, &id.0.to_ne_bytes())
    }

    fn put_key(&mut self, index_key: IndexKey) -> Result<()> {
        let dbi = self.index_dbi(&index_key.index);
        self.put(dbi, &full_index_key(&index_key), &[])
    }

    fn del_key(&mut self, index_key: IndexKey) -> Result<()> {
        let dbi = self.index_dbi(&index_key.index);
        self.del(dbi, &full_index_key(&index_key))
    }

    fn commit(self) -> Result<()> {
        // nothing else may be using this transaction after it's committed
        let txn = Rc::try_unwrap(self.inner).map_err(|_| {
            DatabaseError::Lmdb("can't commit a transaction that is still in use".to_string())
        })?;

        let rc = unsafe { ffi::mdb_txn_commit(txn.txn) };
        txn.committed.set(true);
        check(rc)
    }
}

struct CursorGuard(*mut ffi::MDB_cursor);

impl Drop for CursorGuard {
    fn drop(&mut self) {
        unsafe { ffi::mdb_cursor_close(self.0) };
    }
}

fn val(bytes: &[u8]) -> ffi::MDB_val {
    ffi::MDB_val {
        mv_size: bytes.len(),
        mv_data: bytes.as_ptr() as *mut _,
    }
}

/// safety: the value must have been filled by LMDB and still be valid
unsafe fn slice<'a>(val: &ffi::MDB_val) -> &'a [u8] {
    if val.mv_size == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(val.mv_data as *const u8, val.mv_size) }
}

fn check(rc: std::os::raw::c_int) -> Result<()> {
    if rc == 0 {
        return Ok(());
    }

    let message = unsafe {
        let ptr = ffi::mdb_strerror(rc);
        if ptr.is_null() {
            format!("unknown error {}", rc)
        } else {
            std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };
    Err(DatabaseError::Lmdb(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::tests::{PK1, event, query};

    fn temp_db() -> (LMDBEventDatabase, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            LMDBEventDatabase::open_with_map_size(dir.path(), 1 << 26).unwrap(),
            dir,
        )
    }

    mod suite {
        crate::database::tests::database_test_suite!(super::temp_db());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = LMDBEventDatabase::open(dir.path()).unwrap();
            db.save_event(&event(1, PK1, 1, 10, vec![])).unwrap();
            db.save_event(&event(2, PK1, 1, 20, vec![])).unwrap();
        }

        let db = LMDBEventDatabase::open(dir.path()).unwrap();
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

    #[test]
    fn read_refs_are_zero_copy() {
        let (db, _dir) = temp_db();
        db.save_event(&event(1, PK1, 1, 10, vec![])).unwrap();

        let txn = db.begin_read_txn().unwrap();
        let evt = txn
            .get_event(event(1, PK1, 1, 10, vec![]).id.short())
            .unwrap();
        assert!(matches!(evt.0, EventBytes::Mapped { .. }));
        assert_eq!(evt.content.as_str(), "event 1");
    }
}
