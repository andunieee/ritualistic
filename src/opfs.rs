//! a redb storage backend for the browser's origin private file system, usable from the main
//! thread.
//!
//! fedimint-cursed-redb backs redb with a `FileSystemSyncAccessHandle`, but those only exist in
//! web workers, and apps that draw their ui from rust run on the main thread. so here the whole
//! database lives in memory, and each `sync_data` from redb schedules an asynchronous save of the
//! chunks that changed through a `FileSystemWritableFileStream`. such a stream writes to a swap
//! file that replaces the real one atomically on `close()`, so the saved file is always something
//! redb could have crashed in, never a torn mix.
//!
//! the cost is durability: a commit returns before it is saved, so closing the tab right after it
//! can lose it (without corrupting anything). browsers also copy the whole file into the swap file
//! on each save, so this is meant for databases of a few megabytes, not gigabytes.

use std::io;
use std::sync::{Arc, Mutex};

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    FileSystemCreateWritableOptions, FileSystemDirectoryHandle, FileSystemFileHandle,
    FileSystemGetFileOptions, FileSystemWritableFileStream, StorageManager, WriteCommandType,
    WriteParams,
};

use crate::pages::{Changes, Pages};

#[derive(Clone)]
pub struct OpfsBackend {
    shared: Arc<Mutex<Shared>>,
}

struct Shared {
    name: String,
    file: FileSystemFileHandle,
    pages: Pages,
    /// a save task is running
    saving: bool,
    /// redb asked for a sync since the running save took its changes
    pending: bool,
}

// SAFETY: wasm32-unknown-unknown has a single thread, so the js handles never cross threads
unsafe impl Send for OpfsBackend {}
unsafe impl Sync for OpfsBackend {}

impl std::fmt::Debug for OpfsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.shared.lock().unwrap();
        f.debug_struct("OpfsBackend")
            .field("name", &s.name)
            .field("len", &s.pages.len())
            .finish()
    }
}

impl OpfsBackend {
    /// open (or create) the file `name` at the root of the origin private file system and load
    /// it into memory. works on the main thread and in workers.
    pub async fn open(name: &str) -> io::Result<Self> {
        let navigator = js_sys::Reflect::get(&js_sys::global(), &"navigator".into()).map_err(js)?;
        let storage: StorageManager = js_sys::Reflect::get(&navigator, &"storage".into())
            .map_err(js)?
            .dyn_into()
            .map_err(|_| io::Error::other("navigator.storage is not available"))?;
        let root: FileSystemDirectoryHandle = JsFuture::from(storage.get_directory())
            .await
            .map_err(js)?
            .unchecked_into();

        let options = FileSystemGetFileOptions::new();
        options.set_create(true);
        let file: FileSystemFileHandle =
            JsFuture::from(root.get_file_handle_with_options(name, &options))
                .await
                .map_err(js)?
                .unchecked_into();
        let blob: web_sys::File = JsFuture::from(file.get_file())
            .await
            .map_err(js)?
            .unchecked_into();
        let buffer = JsFuture::from(blob.array_buffer()).await.map_err(js)?;
        let data = js_sys::Uint8Array::new(&buffer).to_vec();

        Ok(Self {
            shared: Arc::new(Mutex::new(Shared {
                name: name.to_string(),
                file,
                pages: Pages::new(data),
                saving: false,
                pending: false,
            })),
        })
    }

    /// resolves once everything synced so far is saved, or a save failed. keep a clone of the
    /// backend before handing it to redb to call this.
    pub async fn flushed(&self) {
        loop {
            {
                let s = self.shared.lock().unwrap();
                if !s.saving {
                    return;
                }
            }
            tokio_with_wasm::alias::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    fn save_soon(&self) {
        {
            let mut s = self.shared.lock().unwrap();
            s.pending = true;
            if s.saving {
                return;
            }
            s.saving = true;
        }
        let shared = self.shared.clone();
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                let (name, file, changes) = {
                    let mut s = shared.lock().unwrap();
                    let changes = std::mem::take(&mut s.pending)
                        .then(|| s.pages.take_changes())
                        .flatten();
                    let Some(changes) = changes else {
                        s.saving = false;
                        return;
                    };
                    (s.name.clone(), s.file.clone(), changes)
                };
                if let Err(err) = save(&file, &changes).await {
                    // keep them for the next sync to try again
                    log::error!("failed to save {name} to the opfs: {}", describe(&err));
                    let mut s = shared.lock().unwrap();
                    s.pages.restore(changes);
                    s.saving = false;
                    return;
                }
            }
        });
    }
}

async fn save(file: &FileSystemFileHandle, changes: &Changes) -> Result<(), JsValue> {
    let options = FileSystemCreateWritableOptions::new();
    options.set_keep_existing_data(true);
    let stream: FileSystemWritableFileStream =
        JsFuture::from(file.create_writable_with_options(&options))
            .await?
            .unchecked_into();

    let written = async {
        JsFuture::from(stream.truncate_with_f64(changes.truncate_to as f64)?).await?;
        if changes.len != changes.truncate_to {
            JsFuture::from(stream.truncate_with_f64(changes.len as f64)?).await?;
        }
        for (offset, bytes) in &changes.writes {
            let params = WriteParams::new(WriteCommandType::Write);
            params.set_position(Some(*offset as f64));
            params.set_data(&js_sys::Uint8Array::from(&bytes[..]));
            JsFuture::from(stream.write_with_write_params(&params)?).await?;
        }
        Ok::<_, JsValue>(())
    }
    .await;

    match written {
        // only now does the file change, all at once
        Ok(()) => JsFuture::from(stream.close()).await.map(|_| ()),
        Err(err) => {
            let _ = JsFuture::from(stream.abort()).await;
            Err(err)
        }
    }
}

impl redb::StorageBackend for OpfsBackend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.shared.lock().unwrap().pages.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.shared.lock().unwrap().pages.read(offset, out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.shared.lock().unwrap().pages.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.save_soon();
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.shared.lock().unwrap().pages.write(offset, data)
    }

    fn close(&self) -> io::Result<()> {
        self.save_soon();
        Ok(())
    }
}

fn js(err: JsValue) -> io::Error {
    io::Error::other(describe(&err))
}

fn describe(err: &JsValue) -> String {
    if let Some(e) = err.dyn_ref::<js_sys::Error>() {
        return String::from(e.message());
    }
    err.as_string().unwrap_or_else(|| format!("{err:?}"))
}
