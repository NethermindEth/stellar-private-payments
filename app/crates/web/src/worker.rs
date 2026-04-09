use anyhow::Result;
use wasm_bindgen::JsError;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::oneshot::oneshot;
use gloo_timers::future::TimeoutFuture;
use state::{Storage, process_events};
use std::cell::RefCell;
use crate::protocol::{WorkerRequest, WorkerResponse, UserKeys};
use wasm_bindgen_futures::spawn_local;
use gloo_worker::Registrable;
use prover::{flows::{DepositParams, WithdrawParams, TransferParams, TransactParams, TransactOutput, TransactInputNote,
    deposit, withdraw, transfer, transact, TransactArtifacts},  encryption::derive_encryption_and_note_keypairs};
use futures::channel::mpsc;
use futures::stream::StreamExt;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response, WorkerGlobalScope};
use witness::WitnessCalculator;
use wasm_bindgen::JsValue;
use types::{PublicKeyEntry, SpendingSignature, EncryptionSignature, EncryptionKeyPair, NoteKeyPair, ExtData};
use stellar::hash_ext_data_offchain;

// TODO make it dependent on the network during the compilation
const PROVING_KEY: &[u8] = include_bytes!("../../../../scripts/testdata/policy_tx_2_2_proving_key.bin");
const VERIFICATION_KEY: &str = include_str!("../../../../scripts/testdata/policy_tx_2_2_vk.json");

// TODO for now it is a mix of async (because we want an async bridge for the main thread) and sync (blocking) code
// in the future we should refactor to use wasm threads?


thread_local! {
    static STORAGE: RefCell<Option<Storage>> = RefCell::new(None);
    // signalling the events processor
    static PROCESSOR_TX: RefCell<Option<mpsc::Sender<()>>> = RefCell::new(None);
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

    let wasm_bytes = fetch_circuit_file("/circuits/policy_tx_2_2.wasm").await?;
    log::debug!("[WORKER] fetched policy_tx_2_2.wasm: {} bytes", wasm_bytes.len());
    let r1cs_bytes = fetch_circuit_file("/circuits/policy_tx_2_2.r1cs").await?;
    log::debug!("[WORKER] fetched policy_tx_2_2.r1cs: {} bytes", r1cs_bytes.len());

    let witness_calc = WitnessCalculator::new(&wasm_bytes, &r1cs_bytes).expect("FAILED WitnessCalculator");

    let storage = state::Storage::connect().map_err(|e| JsError::new(&e.to_string()))?;

    STORAGE.with(|s| {
        *s.borrow_mut() = Some(storage);
    });

    let (tx, rx) = mpsc::channel::<()>(1);

    PROCESSOR_TX.with(|cell| {
        *cell.borrow_mut() = Some(tx);
    });

    spawn_local(async move {
        run_processor_loop(rx).await;
    });

    log::debug!("[WORKER] initialized");

    Ok(())
}

#[oneshot]
pub(crate) async fn Worker(req: WorkerRequest) -> WorkerResponse {
    match router(req).await {
        Ok(r) => r,
        Err(e) => WorkerResponse::Error(e.to_string())
    }
}

// Main router of worker requests
pub(crate) async fn router(req: WorkerRequest) -> Result<WorkerResponse> {
    let resp = match req {
        WorkerRequest::Ping => {
            log::debug!("[WORKER] ping");
            loop {
                let ready = STORAGE.with(|s| s.borrow().is_some());

                if ready {
                    log::debug!("[WORKER] pong");
                    kick_processor();
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
            kick_processor();
            WorkerResponse::Saved
        }
        WorkerRequest::DeriveSaveUserKeys(address, spending_signature, encryption_signature) => {
            log::debug!("[WORKER] deriving and saving user keys for the account {address}");
            let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(spending_signature, encryption_signature)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair)?)?;
            log::debug!("[WORKER] saved notes and encryption keys for the account {address}");
            kick_processor();
            WorkerResponse::Saved
        }
        WorkerRequest::UserKeys(address) => {
            log::debug!("[WORKER] fetch user keys for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            if opt.is_some() {
                log::debug!("[WORKER] fetched notes and encryption keys for the account {address}");
            } else {
                log::debug!("[WORKER] not found notes and encryption keys for the account {address}");
            }
            WorkerResponse::UserKeys(opt.map(|(note_keypair, encryption_keypair)| UserKeys{note_keypair, encryption_keypair}))
        }
        WorkerRequest::RecentPubKeys(limit) => {
            log::debug!("[WORKER] fetch pub keys for the address book");
            let list = with_storage!(s => s.get_recent_public_keys(limit)?)?;
            log::debug!("[WORKER] fetched {} pub keys for the address book", list.len());
            WorkerResponse::PubKeys(list)
        }
        // WorkerRequest::Deposit(address, amount_stroops, pool_root, pool_address, non_membership_proof) => {
        //     log::debug!("[WORKER] deposit");
        //     let (priv_key, encryption_pubkey) = match with_storage!(s => s.get_user_keys(&address)?)? {
        //         Some((NoteKeyPair{private, ..}, EncryptionKeyPair{public,..})) => (private, public),
        //         None => return Ok(WorkerResponse::Error(format!("address {} should generate note and encryption keys first"))),
        //     };

        //     let membership_proof =

        //     let params = DepositParams {
        //         priv_key,
        //         encryption_pubkey,
        //         pool_root,
        //         pool_address,
        //         amount_stroops
        //         outputs: Vec<TransactOutput>,

        //         /// ASP membership proof data required by the circuit (provided by caller).
        //         pub membership_proof: AspMembershipProof,
        //         /// ASP non-membership proof data required by the circuit (provided by caller).
        //         pub non_membership_proof: AspNonMembershipProof,
        //         /// Pool Merkle tree depth.
        //         pub tree_depth: usize,
        //         /// ASP sparse Merkle tree depth.
        //         pub smt_depth: usize,
        //     }
        //     let transact_artifacts = flows::deposit(params, hash_ext_data_offchain)?;

        //     WorkerResponse::PubKeys(list)
        // }
    };
    Ok(resp)
}

fn kick_processor() {
    PROCESSOR_TX.with(|cell| {
        if let Some(tx) = cell.borrow_mut().as_mut() {
            let _ = tx.try_send(());
        }
    });
}

async fn run_processor_loop(mut rx: mpsc::Receiver<()>) {
    while let Some(()) = rx.next().await {
        if let Err(e) = process_until_empty().await {
            log::error!("[WORKER] events processing failed: {e:#}");
        }
    }
}

async fn process_until_empty() -> anyhow::Result<()> {
    const FETCH_LIMIT: u32 = 50; // small chunks to stay responsive

    loop {
        let processed = with_storage_mut!(s => process_events(s, FETCH_LIMIT)?)?;
        if !processed {
            break;
        }
        // Yield to avoid blocking the worker for a long time
        gloo_timers::future::TimeoutFuture::new(0).await;
    }

    Ok(())
}

async fn fetch_circuit_file(path: &str) -> Result<Vec<u8>, JsError> {
    let global = js_sys::global();

    let location = js_sys::Reflect::get(&global, &JsValue::from_str("location"))
        .map_err(|_| JsError::new("Accessing self.location failed"))?;

    let origin = js_sys::Reflect::get(&location, &JsValue::from_str("origin"))
        .map_err(|_| JsError::new("Accessing self.location.origin failed"))?
        .as_string()
        .ok_or_else(|| JsError::new("Origin is not a string"))?;


    let url_string = if path.starts_with("http") {
        path.to_string()
    } else {
        format!("{}{}", origin, path)
    };

    log::debug!("[WORKER] Fetching from: {}", url_string);

    let mut opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&url_string, &opts)
        .map_err(|e| JsError::new(&format!("Request failed for {}: {:?}", url_string, e)))?;

    let global_scope = global.unchecked_into::<web_sys::WorkerGlobalScope>();
    let resp_value = JsFuture::from(global_scope.fetch_with_request(&request))
        .await
        .map_err(|e| JsError::new(&format!("Network error: {:?}", e)))?;

    let resp: web_sys::Response = resp_value.dyn_into().map_err(|_| {
        JsError::new("Failed to cast response")
    })?;

    if !resp.ok() {
        return Err(JsError::new(&format!("HTTP {} for {}", resp.status(), url_string)));
    }

    let array_buffer_promise = resp.array_buffer().map_err(|e| JsError::new(&format!("{:?}", e)))?;
    let array_buffer_value = JsFuture::from(array_buffer_promise).await
        .map_err(|e| JsError::new(&format!("{:?}", e)))?;

    let type_array = js_sys::Uint8Array::new(&array_buffer_value);
    Ok(type_array.to_vec())
}
