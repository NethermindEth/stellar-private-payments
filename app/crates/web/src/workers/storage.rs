use anyhow::Result;
use wasm_bindgen::JsError;
use sqlite_wasm_vfs::sahpool::{install as install_opfs_sahpool, OpfsSAHPoolCfg};
use gloo_worker::oneshot::oneshot;
use gloo_timers::future::TimeoutFuture;
use state::{Storage, process_events, process_notes, AccountKeys, PoolCommitmentRow, DerivedUserNoteRow};
use std::cell::RefCell;
use crate::protocol::{StorageWorkerRequest, StorageWorkerResponse, UserKeys, AdminASPRequest};
use wasm_bindgen_futures::spawn_local;
use gloo_worker::Registrable;
use prover::{
    crypto::asp_membership_leaf,
    encryption::{derive_encryption_and_note_keypairs, generate_random_blinding},
    flows::{DepositParams, TransactOutput},
    merkle::{from_leaves, MerkleProof},
};
use futures::channel::mpsc;
use futures::stream::StreamExt;
use types::{
    AspMembershipSync, AspMembershipProof, EncryptionKeyPair, NoteKeyPair
};

// TODO for now it is a mix of async (because we want an async bridge for the main thread) and sync (blocking) code
// in the future we should refactor to use wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

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
    StorageWorker::registrar().register();
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[{WORKER_NAME}] init failed: {e:?}");
        }
    });
}

async fn init() -> Result<(), JsError> {
    install_opfs_sahpool::<sqlite_wasm_rs::WasmOsCallback>(
        &OpfsSAHPoolCfg::default(),
        true,
    )
    .await.map_err(|e| {
        log::error!("[{WORKER_NAME}] fatal error installing OPFS Sqlite VFS: {e:?}");
        e
    })?;

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

    log::debug!("[{WORKER_NAME}] initialized");

    Ok(())
}

#[oneshot]
pub(crate) async fn StorageWorker(req: StorageWorkerRequest) -> StorageWorkerResponse {
    match router(req).await {
        Ok(r) => r,
        Err(e) => StorageWorkerResponse::Error(e.to_string())
    }
}

// Main router of worker requests
pub(crate) async fn router(req: StorageWorkerRequest) -> Result<StorageWorkerResponse> {
    let resp = match req {
        StorageWorkerRequest::Ping => {
            log::debug!("[{WORKER_NAME}] ping");
            loop {
                let ready = STORAGE.with(|s| s.borrow().is_some());

                if ready {
                    log::debug!("[{WORKER_NAME}] pong");
                    kick_processor();
                    return Ok(StorageWorkerResponse::Pong);
                }

                TimeoutFuture::new(50).await;
            }
        }
        StorageWorkerRequest::SyncState => {
            log::debug!("[{WORKER_NAME}] get current sync");
            let state = with_storage!(s => s.get_sync_metadata()?)?;
            let resp = StorageWorkerResponse::SyncState(state);
            log::debug!("[{WORKER_NAME}] sending current sync");
            resp
        }
        StorageWorkerRequest::SaveEvents(events_data) => {
            log::debug!("[{WORKER_NAME}] saving {} raw contract events", events_data.events.len());
            with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            // We could pass the events_data here further for the processing but
            // for the sake of the sequential processing we drop it here
            // the storage is the single source of raw events for the processors
            log::debug!("[{WORKER_NAME}] sending {} raw contract events to process", events_data.events.len());
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DeriveSaveUserKeys(address, spending_signature, encryption_signature) => {
            log::debug!("[{WORKER_NAME}] deriving and saving user keys for the account {address}");
            let (note_keypair, encryption_keypair) = derive_encryption_and_note_keypairs(spending_signature, encryption_signature)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair)?)?;
            log::debug!("[{WORKER_NAME}] saved notes and encryption keys for the account {address}");
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UserKeys(address) => {
            log::debug!("[{WORKER_NAME}] fetch user keys for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            if opt.is_some() {
                log::debug!("[{WORKER_NAME}] fetched notes and encryption keys for the account {address}");
            } else {
                log::debug!("[{WORKER_NAME}] not found notes and encryption keys for the account {address}");
            }
            StorageWorkerResponse::UserKeys(opt.map(|(note_keypair, encryption_keypair)| UserKeys{note_keypair, encryption_keypair}))
        }
        StorageWorkerRequest::RecentPubKeys(limit) => {
            log::debug!("[{WORKER_NAME}] fetch pub keys for the address book");
            let list = with_storage!(s => s.get_recent_public_keys(limit)?)?;
            log::debug!("[{WORKER_NAME}] fetched {} pub keys for the address book", list.len());
            StorageWorkerResponse::PubKeys(list)
        }
        StorageWorkerRequest::DeriveASPleaf(AdminASPRequest{membership_blinding, pubkey}) => {
            log::debug!("[{WORKER_NAME}] derive user leaf from the pubkey for the admin");
            let user_leaf = asp_membership_leaf(&pubkey, &membership_blinding)?;
            log::debug!("[{WORKER_NAME}] derived user leaf from the pubkey for the admin");
            StorageWorkerResponse::DeriveASPleaf(user_leaf)
        }
        StorageWorkerRequest::Deposit(req) => {
            log::debug!("[{WORKER_NAME}] deposit");

            let (note_privkey, note_pubkey, encryption_pubkey) =
                match with_storage!(s => s.get_user_keys(&req.user_address)?)? {
                    Some((
                        NoteKeyPair {
                            private,
                            public: note_pub,
                        },
                        EncryptionKeyPair {
                            public: enc_pub, ..
                        },
                    )) => (private, note_pub, enc_pub),
                    None => {
                        return Ok(StorageWorkerResponse::Error(format!(
                            "address {} should generate note and encryption keys first",
                            req.user_address
                        )))
                    }
                };

            let user_leaf = asp_membership_leaf(&note_pubkey, &req.membership_blinding)?;
            let user_leaf_index = match with_storage!(s => s.check_asp_membership_precondition(
                &user_leaf,
                &req.aspmem_root,
                req.aspmem_ledger
            )?)? {
                AspMembershipSync::UserIndex(user_leaf_index) => user_leaf_index,
                status => {
                    log::debug!("[{WORKER_NAME}] asp membership check is not fully synced");
                    return Ok(StorageWorkerResponse::AspMembershipSync(status));
                }
            };

            let asp_membership_merkle_tree_leaves =
                with_storage!(s => s.get_all_asp_membership_leaves_ordered()?)?;
            let tree_depth_usize =
                usize::try_from(req.tree_depth).map_err(|_| anyhow::anyhow!("tree_depth too large"))?;
            let aspmembership_tree =
                from_leaves(tree_depth_usize, asp_membership_merkle_tree_leaves.into_iter())?;
            let MerkleProof {
                path_indices,
                path_elements,
                root,
                ..
            } = aspmembership_tree.get_proof(user_leaf_index)?;

            let note_pubkey_for_outputs = note_pubkey.clone();
            let encryption_pubkey_for_outputs = encryption_pubkey.clone();
            let outputs = req
                .output_amounts
                .into_iter()
                .map(|amount_stroops| {
                    Ok(TransactOutput {
                        amount_stroops,
                        blinding: generate_random_blinding()?,
                        recipient_note_pubkey: Some(note_pubkey_for_outputs.clone()),
                        recipient_encryption_pubkey: Some(encryption_pubkey_for_outputs.clone()),
                    })
                })
                .collect::<Result<Vec<_>>>()?;

            let params = DepositParams {
                priv_key: note_privkey,
                encryption_pubkey: encryption_pubkey.clone(),
                pool_root: req.pool_root.expect("TODO - figure out on NOne"),
                pool_address: req.pool_address,
                amount_stroops: req.amount_stroops,
                outputs,
                membership_proof: AspMembershipProof {
                    leaf: user_leaf,
                    blinding: req.membership_blinding,
                    path_elements,
                    path_indices,
                    root,
                },
                non_membership_proof: req.non_membership_proof,
                tree_depth: req.tree_depth,
                smt_depth: req.smt_depth,
            };

            StorageWorkerResponse::DepositParams(params)
        }
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
            log::error!("[{WORKER_NAME}] events processing failed: {e:#}");
        }
    }
}

async fn process_until_empty() -> anyhow::Result<()> {
    const FETCH_LIMIT: u32 = 50; // small chunks to stay responsive

    loop {
        let did_raw = with_storage_mut!(s => process_events(s, FETCH_LIMIT)?)?;
        let mut derive = |account: &AccountKeys,
                          row: &PoolCommitmentRow|
         -> anyhow::Result<Option<DerivedUserNoteRow>> {
            let opt = prover::notes::try_decrypt_and_derive_user_note(
                &account.note_keypair,
                &account.encryption_keypair.private,
                &row.commitment,
                row.leaf_index,
                &row.encrypted_output,
            )?;
            Ok(opt.map(|d| DerivedUserNoteRow {
                amount: d.amount,
                blinding: d.blinding,
                expected_nullifier: d.expected_nullifier,
            }))
        };
        let did_notes = with_storage_mut!(s => process_notes(s, FETCH_LIMIT, &mut derive)?)?;
        if !did_raw && !did_notes {
            break;
        }
        // Yield to avoid blocking the worker for a long time
        gloo_timers::future::TimeoutFuture::new(0).await;
    }
    Ok(())
}
