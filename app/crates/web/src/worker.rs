use wasm_bindgen::JsError;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::oneshot::oneshot;
use gloo_timers::future::TimeoutFuture;
use state::Storage;
use std::cell::RefCell;
use crate::protocol::{WorkerRequest, WorkerResponse};
use wasm_bindgen_futures::spawn_local;
use gloo_worker::Registrable;

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../scripts/testdata/policy_tx_2_2_vk.json");

thread_local! {
    // RefCell allows us to borrow the client as mutable
    static STORAGE: RefCell<Option<Storage>> = RefCell::new(None);
}

pub fn worker_main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    Worker::registrar().register();
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
    .await.map_err(|e| {
        log::debug!("[WORKER] fatal error installing OPFS Sqlite VFS: {e:?}");
        e
    })?;

    let storage = state::Storage::connect().map_err(|e| JsError::new(&e.to_string()))?;

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });

    log::debug!("[WORKER] initialized");

    Ok(())
}

// Main router of worker requests
#[oneshot]
pub(crate) async fn Worker(req: WorkerRequest) -> WorkerResponse {
    match req {
        WorkerRequest::Ping => {
            log::debug!("[WORKER] ping");
            loop {
                let ready = STORAGE.with(|s| s.borrow().is_some());

                if ready {
                    log::debug!("[WORKER] pong");
                    break WorkerResponse::Pong;
                }

                TimeoutFuture::new(50).await;
            }
        }
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
            // We could pass the events_data here further for the processing but
            // for the sake of the sequential processing we drop it here
            // the storage is the single source of raw events for the processors
            log::debug!("[WORKER] sending {} raw contract events to process", events_data.events.len());
            resp
        }
    }
}
