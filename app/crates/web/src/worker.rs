use anyhow::Result;
use wasm_bindgen::JsError;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::oneshot::oneshot;
use gloo_timers::future::TimeoutFuture;
use state::Storage;
use std::cell::RefCell;
use crate::protocol::{WorkerRequest, WorkerResponse, UserKeys};
use wasm_bindgen_futures::spawn_local;
use gloo_worker::Registrable;
use prover::encryption::derive_encryption_and_note_keypairs;

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../scripts/testdata/policy_tx_2_2_vk.json");

thread_local! {
    // RefCell allows us to borrow the client as mutable
    static STORAGE: RefCell<Option<Storage>> = RefCell::new(None);
}

macro_rules! with_storage {
    ($storage:ident => $body:expr) => {
        STORAGE.with(|s| {
            let borrow = s.borrow();
            // We must return the Result from the closure
            let $storage = borrow.as_ref()
                .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;

            // This ensures the body expression's Result is returned by the closure
            Ok::<_, anyhow::Error>($body)
        })
    };
}

macro_rules! with_storage_mut {
    ($storage:ident => $body:expr) => {
        STORAGE.with(|s| {
            let mut borrow = s.borrow_mut();
            let $storage = borrow.as_mut()
                .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;

            Ok::<_, anyhow::Error>($body)
        })
    };
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
    match router(req).await {
        Ok(r) => r,
        Err(e) => WorkerResponse::Error(e.to_string())
    }
}

pub(crate) async fn router(req: WorkerRequest) -> Result<WorkerResponse> {
    let resp = match req {
        WorkerRequest::Ping => {
            log::debug!("[WORKER] ping");
            loop {
                let ready = STORAGE.with(|s| s.borrow().is_some());

                if ready {
                    log::debug!("[WORKER] pong");
                    return Ok(WorkerResponse::Pong);
                }

                TimeoutFuture::new(50).await;
            }
        }
        WorkerRequest::SyncState => {
            log::debug!("[WORKER] get current sync");
            let state = with_storage!(s => s.get_sync_metadata()?)?;
            let resp = WorkerResponse::SyncState(state);
            log::debug!("[WORKER] sending current sync");
            resp
        }
        WorkerRequest::SaveEvents(events_data) => {
            log::debug!("[WORKER] saving {} raw contract events", events_data.events.len());
            with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            // We could pass the events_data here further for the processing but
            // for the sake of the sequential processing we drop it here
            // the storage is the single source of raw events for the processors
            log::debug!("[WORKER] sending {} raw contract events to process", events_data.events.len());
            WorkerResponse::Saved
        }
        WorkerRequest::DeriveSaveUserKeys(address, spending_signature, encryption_signature) => {
            log::debug!("[WORKER] deriving and saving user keys for the account {address}");
            let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(spending_signature, encryption_signature)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair)?)?;
            log::debug!("[WORKER] saved notes and encryption keys for the account {address}");
            WorkerResponse::Saved
        }
        WorkerRequest::UserKeys(address) => {
            log::debug!("[WORKER] fetch user keys for the account {address}");
            let (note_keypair, encryption_keypair) = with_storage!(s => s.get_user_keys(&address)?)?;
            log::debug!("[WORKER] fetched notes and encryption keys for the account {address}");
            WorkerResponse::UserKeys(UserKeys{note_keypair, encryption_keypair})
        }
    };
    Ok(resp)
}
