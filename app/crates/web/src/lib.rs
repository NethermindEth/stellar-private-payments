use serde::{Deserialize, Serialize};
use wasm_bindgen::JsError;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::oneshot::oneshot;
use state::Storage;
use std::cell::RefCell;

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerRequest {
    SyncState,
    SaveEvents(types::ContractsEventData),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum WorkerResponse {
    SyncState(Option<types::SyncMetadata>),
    Saved,
    Error(String),
}

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../scripts/testdata/policy_tx_2_2_vk.json");

thread_local! {
    // RefCell allows us to borrow the client as mutable
    static STORAGE: RefCell<Option<Storage>> = RefCell::new(None);
}

pub async fn init() -> Result<(), JsError> {
    install_opfs_sahpool::<sqlite_wasm_rs::WasmOsCallback>(
        &OpfsSAHPoolCfg::default(),
        true,
    )
    .await.map_err(|e| {
        log::debug!("[WORKER] error installing OPFS Sqlite pool: {e:?}");
        e
    })?;

    let storage = state::Storage::connect().map_err(|e| JsError::new(&e.to_string()))?;

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });

    log::debug!("[WORKER] initialized");

    Ok(())
}

#[oneshot]
pub async fn Worker(req: WorkerRequest) -> WorkerResponse {
    match req {
        WorkerRequest::SyncState => {
            log::debug!("[WORKER] get current sync");
            let resp = STORAGE.with(|s| {
                let storage_borrow = s.borrow();

                match storage_borrow.as_ref() {
                    Some(storage) => match storage.get_sync_metadata() {
                        Ok(v) => WorkerResponse::SyncState(v),
                        Err(e) => WorkerResponse::Error(e.to_string()),
                    },
                    None => WorkerResponse::Error("storage is not initialized".into()),
                }
            });
            log::debug!("[WORKER] sending current sync");
            resp
        }
        WorkerRequest::SaveEvents(events_data) => {
            log::debug!("[WORKER] saving {} raw contract events", events_data.events.len());
            let resp = STORAGE.with(|s| {
                let mut storage_borrow = s.borrow_mut();
                match storage_borrow.as_mut() {
                    Some(storage) => match storage.save_events_batch(&events_data) {
                        Ok(()) => WorkerResponse::Saved,
                        Err(e) => WorkerResponse::Error(e.to_string()),
                    },
                    None => WorkerResponse::Error("storage is not initialized".into()),
                }
            });
            log::debug!("[WORKER] sending {} raw contract events to process", events_data.events.len());
            resp
        }
    }
}
