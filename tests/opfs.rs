//! the redb opfs backend, in a real browser, e.g. with wasm-bindgen-test-runner and chromedriver
#![cfg(all(target_arch = "wasm32", feature = "redb"))]

use redb::{ReadableDatabase, ReadableTableMetadata, TableDefinition};
use ritualistic::OpfsBackend;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;
use web_sys::{FileSystemDirectoryHandle, StorageManager};

wasm_bindgen_test_configure!(run_in_browser);

const T: TableDefinition<u64, &[u8]> = TableDefinition::new("t");

async fn remove(name: &str) {
    let navigator = js_sys::Reflect::get(&js_sys::global(), &"navigator".into()).unwrap();
    let storage: StorageManager = js_sys::Reflect::get(&navigator, &"storage".into())
        .unwrap()
        .unchecked_into();
    let root: FileSystemDirectoryHandle = JsFuture::from(storage.get_directory())
        .await
        .unwrap()
        .unchecked_into();
    let _ = JsFuture::from(root.remove_entry(name)).await;
}

#[wasm_bindgen_test]
async fn survives_reopening() {
    let name = "ritualistic-test-reopen.redb";
    remove(name).await;
    {
        let backend = OpfsBackend::open(name).await.unwrap();
        let handle = backend.clone();
        let db = redb::Database::builder()
            .create_with_backend(backend)
            .unwrap();
        for i in 0..50u64 {
            let txn = db.begin_write().unwrap();
            txn.open_table(T)
                .unwrap()
                .insert(i, vec![i as u8; 3000].as_slice())
                .unwrap();
            txn.commit().unwrap();
        }
        drop(db);
        handle.flushed().await;
    }

    let db = redb::Database::builder()
        .create_with_backend(OpfsBackend::open(name).await.unwrap())
        .unwrap();
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(T).unwrap();
    assert_eq!(t.len().unwrap(), 50);
    assert_eq!(t.get(49).unwrap().unwrap().value(), &[49u8; 3000][..]);
    drop(t);
    drop(txn);
    drop(db);
    remove(name).await;
}
