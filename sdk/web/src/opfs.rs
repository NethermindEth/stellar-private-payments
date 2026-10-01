//! Turso I/O backed by OPFS synchronous handles in a dedicated browser worker.
//!
//! JavaScript handles never cross threads: only session identifiers live in the
//! Send + Sync I/O objects. This SDK uses single-threaded WASM workers;
//! building this backend with shared-memory WASM requires a different I/O
//! design.

use anyhow::{Context, Result};
use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    sync::Arc,
};
use stellar_private_payments::state::SqliteStorage;
use turso_core::{
    Buffer, Clock, Completion, File, IO, LimboError, OpenFlags,
    io::{
        FileId, FileSyncType,
        clock::{MonotonicInstant, WallClockInstant},
    },
};
use wasm_bindgen::prelude::*;

#[cfg(target_feature = "atomics")]
compile_error!("The OPFS backend requires single-threaded WASM workers");

#[wasm_bindgen(module = "/src/opfs.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = openFiles)]
    async fn open_files(directory: &str) -> std::result::Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = closeFiles)]
    fn close_files(files: &JsValue);
    #[wasm_bindgen(catch, js_name = isInitialized)]
    fn is_initialized(files: &JsValue) -> std::result::Result<bool, JsValue>;
    #[wasm_bindgen(catch, js_name = initializeFiles)]
    fn initialize_files(files: &JsValue) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = markReady)]
    fn mark_ready(files: &JsValue) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = readFile)]
    fn read_file(
        files: &JsValue,
        slot: u32,
        buffer: &mut [u8],
        offset: f64,
    ) -> std::result::Result<u32, JsValue>;
    #[wasm_bindgen(catch, js_name = writeFile)]
    fn write_file(
        files: &JsValue,
        slot: u32,
        buffer: &[u8],
        offset: f64,
    ) -> std::result::Result<u32, JsValue>;
    #[wasm_bindgen(catch, js_name = syncFile)]
    fn sync_file(files: &JsValue, slot: u32) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = truncateFile)]
    fn truncate_file(files: &JsValue, slot: u32, size: f64) -> std::result::Result<(), JsValue>;
    #[wasm_bindgen(catch, js_name = sizeFile)]
    fn size_file(files: &JsValue, slot: u32) -> std::result::Result<f64, JsValue>;
    #[wasm_bindgen(js_name = monotonicMillis)]
    fn monotonic_millis() -> f64;
}

thread_local! {
    static HANDLES: RefCell<HashMap<u64, JsValue>> = RefCell::new(HashMap::new());
    static NEXT_SESSION: Cell<u64> = const { Cell::new(0) };
}

struct Session(u64);

impl Session {
    fn with<T>(
        &self,
        f: impl FnOnce(&JsValue) -> std::result::Result<T, JsValue>,
    ) -> turso_core::Result<T> {
        HANDLES.with(|handles| {
            let handles = handles.borrow();
            let files = handles
                .get(&self.0)
                .ok_or_else(|| io_error("closed OPFS session"))?;
            f(files).map_err(|_| io_error("OPFS file operation failed"))
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        HANDLES.with(|handles| {
            if let Some(files) = handles.borrow_mut().remove(&self.0) {
                close_files(&files);
            }
        });
    }
}

fn io_error(operation: &'static str) -> LimboError {
    turso_core::io_error(std::io::Error::other(operation), operation)
}

fn js_error_name(error: &JsValue) -> String {
    js_sys::Reflect::get(error, &JsValue::from_str("name"))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_else(|| "Error".into())
}

// JavaScript file offsets must be exact, nonnegative integers.
#[allow(clippy::cast_precision_loss)]
fn offset(value: u64) -> turso_core::Result<f64> {
    if value > 9_007_199_254_740_991 {
        return Err(io_error("OPFS offset exceeds safe integer range"));
    }
    Ok(value as f64)
}

struct OpfsIo {
    session: Arc<Session>,
}
struct OpfsFile {
    session: Arc<Session>,
    slot: u32,
}

impl Clock for OpfsIo {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn current_time_monotonic(&self) -> MonotonicInstant {
        MonotonicInstant::from_nanos((monotonic_millis() * 1_000_000.0) as u128)
    }

    fn current_time_wall_clock(&self) -> WallClockInstant {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap_or_default();
        WallClockInstant {
            secs: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            micros: now.subsec_micros(),
        }
    }
}

impl IO for OpfsIo {
    fn open_file(
        &self,
        path: &str,
        _flags: OpenFlags,
        _direct: bool,
    ) -> turso_core::Result<Arc<dyn File>> {
        let slot = match path {
            "spp.db" => 0,
            "spp.db-wal" => 1,
            _ => return Err(io_error("unexpected OPFS database file")),
        };
        Ok(Arc::new(OpfsFile {
            session: self.session.clone(),
            slot,
        }))
    }

    fn remove_file(&self, _path: &str) -> turso_core::Result<()> {
        Err(io_error("OPFS file removal is unsupported"))
    }

    fn file_id(&self, path: &str) -> turso_core::Result<FileId> {
        // Different sessions must not reuse Turso's process-local database
        // cache.
        Ok(FileId::from_path_hash(&format!(
            "{}:{path}",
            self.session.0
        )))
    }

    fn generate_random_number(&self) -> i64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        i64::from_ne_bytes(bytes)
    }

    fn fill_bytes(&self, bytes: &mut [u8]) {
        getrandom::getrandom(bytes).expect("browser cryptographic randomness");
    }
}

impl File for OpfsFile {
    fn lock_file(&self, _exclusive: bool) -> turso_core::Result<()> {
        Ok(())
    }

    fn unlock_file(&self) -> turso_core::Result<()> {
        Ok(())
    }

    fn pread(&self, pos: u64, completion: Completion) -> turso_core::Result<Completion> {
        let offset = offset(pos)?;
        let read = completion.as_read();
        let buffer = read.buf();
        let count = self
            .session
            .with(|files| read_file(files, self.slot, buffer.as_mut_slice(), offset))?;
        completion.complete(i32::try_from(count).map_err(|_| io_error("OPFS read too large"))?);
        Ok(completion)
    }

    fn pwrite(
        &self,
        pos: u64,
        buffer: Arc<Buffer>,
        completion: Completion,
    ) -> turso_core::Result<Completion> {
        let offset = offset(pos)?;
        let count = self
            .session
            .with(|files| write_file(files, self.slot, buffer.as_slice(), offset))?;
        if usize::try_from(count).ok() != Some(buffer.len()) {
            return Err(io_error("short OPFS write"));
        }
        completion.complete(i32::try_from(count).map_err(|_| io_error("OPFS write too large"))?);
        Ok(completion)
    }

    fn sync(&self, completion: Completion, _kind: FileSyncType) -> turso_core::Result<Completion> {
        self.session.with(|files| sync_file(files, self.slot))?;
        completion.complete(0);
        Ok(completion)
    }

    fn truncate(&self, size: u64, completion: Completion) -> turso_core::Result<Completion> {
        let size = offset(size)?;
        self.session
            .with(|files| truncate_file(files, self.slot, size))?;
        completion.complete(0);
        Ok(completion)
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn size(&self) -> turso_core::Result<u64> {
        let size = self.session.with(|files| size_file(files, self.slot))?;
        if !size.is_finite()
            || !(0.0..=9_007_199_254_740_991.0).contains(&size)
            || size.fract() != 0.0
        {
            return Err(io_error("invalid OPFS file size"));
        }
        Ok(size as u64)
    }
}

/// Open a fresh or existing Turso wallet in a dedicated worker.
/// `directory` is relative to OPFS. Legacy SQLite wallets are not imported.
pub async fn open_wallet(directory: &str) -> Result<SqliteStorage> {
    let files = open_files(directory)
        .await
        .map_err(|error| anyhow::anyhow!("OPFS open: {}", js_error_name(&error)))?;
    let id = NEXT_SESSION.with(|next| {
        let id = next.get();
        next.set(id.checked_add(1).expect("OPFS session counter exhausted"));
        id
    });
    HANDLES.with(|handles| handles.borrow_mut().insert(id, files));
    let session = Arc::new(Session(id));
    let initialized = session.with(is_initialized)?;
    if !initialized {
        session
            .with(initialize_files)
            .context("initialize OPFS database")?;
    }
    let io = Arc::new(OpfsIo {
        session: session.clone(),
    });
    let db = turso::Builder::new_local("spp.db")
        .with_io_impl(io)
        .build()
        .await?;
    let storage = SqliteStorage::connect_with_database(db).await?;
    if !initialized {
        session
            .with(mark_ready)
            .context("commit OPFS initialization")?;
    }
    Ok(storage)
}
