use gloo_worker::Registrable;

use wasm_bindgen::JsError;
use wasm_bindgen_futures::spawn_local;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::{HandlerId, Worker as GlooWorker, WorkerScope};
use gloo_worker::oneshot::oneshot;
use serde::{Deserialize, Serialize};
use state::Storage;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use web::sync_worker::{WorkerRequest, WorkerResponse};

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../../scripts/testdata/policy_tx_2_2_vk.json");

thread_local! {
    // RefCell allows us to borrow the client as mutable
    static STORAGE: RefCell<Option<Storage>> = RefCell::new(None);
}

fn main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[WORKER] init failed: {e:?}");
        }
    });
}

async fn init() -> Result<(), JsError> {
    install_opfs_sahpool::<sqlite_wasm_rs::WasmOsCallback>(
        &OpfsSAHPoolCfg::default(),
        true,
    )
    .await?;

    let storage = state::Storage::connect().map_err(|e| JsError::new(&e.to_string()))?;

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });

    log::debug!("[WORKER] initialized");

    Ok(())
}

#[oneshot]
async fn worker(req: WorkerRequest) -> WorkerResponse {
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
