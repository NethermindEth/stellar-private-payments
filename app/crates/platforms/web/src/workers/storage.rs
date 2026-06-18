use crate::protocol::{
    AdminASPRequest, AspSecret, BootnodeConfigPayload, DisclaimerStatePayload, DisclosureInputs,
    PublicEncryptionKeyPair, PublicNoteKeyPair, StorageWorkerRequest, StorageWorkerResponse,
    UserKeys,
};
use anyhow::Result;
use futures::{channel::mpsc, stream::StreamExt};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{Registrable, oneshot::oneshot};
use prover::{
    crypto::asp_membership_leaf,
    encryption::{
        derive_encryption_and_note_keypairs, derive_membership_blinding, generate_random_blinding,
    },
    flows::{N_OUTPUTS, TransactInputNote, TransactOutput, TransactParams},
    merkle::{MerklePrefixTree, MerklePrefixTreeBuilt, MerkleProof},
};
use state::{
    AccountKeys, DerivedUserNoteRow, PoolCommitmentRow, Storage, StoredUserKeys, process_events,
    process_notes,
};
use std::cell::RefCell;
use types::{
    AspMembershipProof, AspMembershipSync, EncryptionKeyPair, Field, NoteAmount, NoteKeyPair,
    NotePublicKey,
};
use wasm_bindgen::JsError;
use wasm_bindgen_futures::spawn_local;

// TODO for now it is a mix of async (because we want an async bridge for the
// main thread) and sync (blocking) code in the future we should refactor to use
// wasm threads?

const WORKER_NAME: &str = "WORKER-STORAGE";

#[derive(Clone, Debug)]
enum InitState {
    Pending,
    Ready,
    Failed(String),
}

#[cfg(target_arch = "wasm32")]
fn is_opfs_locked_error(message: &str) -> bool {
    message.contains("NoModificationAllowedError")
        && (message.contains("createSyncAccessHandle")
            || message.contains("Access Handles cannot be created"))
}

thread_local! {
    static STORAGE: RefCell<Option<Storage>> = const { RefCell::new(None) };
    // signalling the events processor
    static PROCESSOR_TX: RefCell<Option<mpsc::Sender<()>>> = const { RefCell::new(None) };
    static INIT_STATE: RefCell<InitState> = const { RefCell::new(InitState::Pending) };
}

macro_rules! with_storage {
    ($storage:ident => $body:expr) => {
        STORAGE.with(|s| {
            let borrow = s.borrow();
            // We must return the Result from the closure
            let $storage = borrow
                .as_ref()
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
            let $storage = borrow
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("storage is not initialized"))?;

            Ok::<_, anyhow::Error>($body)
        })
    };
}

pub fn worker_main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    log::debug!("[{WORKER_NAME}] starting...");
    StorageWorker::registrar().register();
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[{WORKER_NAME}] init failed: {e:?}");
        }
    });
}

async fn init() -> Result<(), JsError> {
    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Pending);

    #[cfg(target_arch = "wasm32")]
    if let Err(e) = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(
        &sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg::default(),
        true,
    )
    .await
    {
        let debug = format!("{e:?}");
        let text = e.to_string();
        let combined = if text.is_empty() {
            debug.clone()
        } else {
            format!("{text} {debug}")
        };

        let msg = if is_opfs_locked_error(&combined) {
            "Another tab or window is using this app's local database. Please close other tabs/windows running this app, then reload this page.".to_string()
        } else {
            "Failed to initialize local database storage.".to_string()
        };

        log::error!("[{WORKER_NAME}] fatal error installing OPFS Sqlite VFS: {debug}");
        INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
        return Err(JsError::new(&msg));
    }

    let storage = match state::Storage::connect() {
        Ok(storage) => storage,
        Err(e) => {
            let msg = format!("Failed to open local database: {e}");
            INIT_STATE.with(|s| *s.borrow_mut() = InitState::Failed(msg.clone()));
            return Err(JsError::new(&msg));
        }
    };

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

    INIT_STATE.with(|s| *s.borrow_mut() = InitState::Ready);
    log::debug!("[{WORKER_NAME}] initialized");

    Ok(())
}

#[oneshot]
pub(crate) async fn StorageWorker(req: StorageWorkerRequest) -> StorageWorkerResponse {
    match router(req).await {
        Ok(r) => r,
        Err(e) => StorageWorkerResponse::Error(e.to_string()),
    }
}

// Main router of worker requests
pub(crate) async fn router(req: StorageWorkerRequest) -> Result<StorageWorkerResponse> {
    let resp = match req {
        StorageWorkerRequest::Ping => {
            log::trace!("[{WORKER_NAME}] ping");
            loop {
                let state = INIT_STATE.with(|s| s.borrow().clone());
                match state {
                    InitState::Ready => {
                        log::trace!("[{WORKER_NAME}] pong");
                        kick_processor();
                        return Ok(StorageWorkerResponse::Pong);
                    }
                    InitState::Failed(msg) => {
                        log::debug!("[{WORKER_NAME}] ping -> init failed");
                        return Ok(StorageWorkerResponse::Error(msg));
                    }
                    InitState::Pending => {}
                }

                TimeoutFuture::new(50).await;
            }
        }
        StorageWorkerRequest::SyncState => {
            log::trace!("[{WORKER_NAME}] get current sync");
            let state = with_storage!(s => s.get_sync_metadata()?)?;
            let resp = StorageWorkerResponse::SyncState(state);
            log::trace!("[{WORKER_NAME}] sending current sync");
            resp
        }
        StorageWorkerRequest::SaveEvents(events_data) => {
            log::trace!(
                "[{WORKER_NAME}] saving {} raw contract events",
                events_data.events.len()
            );
            with_storage_mut!(s => s.save_events_batch(&events_data)?)?;
            // We could pass the events_data here further for the processing but
            // for the sake of the sequential processing we drop it here
            // the storage is the single source of raw events for the processors
            log::trace!(
                "[{WORKER_NAME}] sending {} raw contract events to process",
                events_data.events.len()
            );
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::SaveSyncProgress {
            metadata,
            fully_indexed,
        } => {
            log::trace!(
                "[{WORKER_NAME}] saving bulk sync progress for {} contracts (fully_indexed={fully_indexed})",
                metadata.len()
            );
            with_storage_mut!(s => s.save_sync_progress(&metadata, fully_indexed)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::ClearIndexingCursors => {
            log::trace!("[{WORKER_NAME}] clearing indexing cursors for RPC handoff");
            with_storage_mut!(s => s.clear_indexing_cursors()?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DeriveSaveUserKeys(address, signature, network_context) => {
            log::trace!("[{WORKER_NAME}] deriving and saving user keys for the account {address}");
            let (note_keypair, encryption_keypair) =
                derive_encryption_and_note_keypairs(signature.clone())?;
            let membership_blinding = derive_membership_blinding(&signature, &network_context)?;
            with_storage_mut!(s => s.save_encryption_and_note_keypairs(&address, &note_keypair, &encryption_keypair, &membership_blinding)?)?;
            log::trace!(
                "[{WORKER_NAME}] saved notes, encryption keys, and ASP secret for the account {address}"
            );
            kick_processor();
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::DisclaimerState(address) => {
            log::trace!("[{WORKER_NAME}] disclaimer state for account {address}");
            let state = with_storage_mut!(s => s.get_disclaimer_state(&address)?)?;
            StorageWorkerResponse::DisclaimerState(DisclaimerStatePayload {
                disclaimer_text_md: state.disclaimer_text_md,
                disclaimer_hash_hex: state.disclaimer_hash_hex,
                accepted: state.accepted,
            })
        }
        StorageWorkerRequest::AcceptDisclaimer(address, disclaimer_hash_hex) => {
            log::trace!("[{WORKER_NAME}] accept disclaimer for account {address}");
            with_storage_mut!(s => s.accept_current_disclaimer(&address, &disclaimer_hash_hex)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::BootnodeConfig => {
            log::trace!("[{WORKER_NAME}] fetch bootnode config");
            let config = with_storage!(s => s.get_bootnode_config()?)?;
            StorageWorkerResponse::BootnodeConfig(BootnodeConfigPayload {
                enabled: config.enabled,
                url: config.url,
            })
        }
        StorageWorkerRequest::SetBootnodeConfig { enabled, url } => {
            log::trace!("[{WORKER_NAME}] set bootnode config enabled={enabled}");
            with_storage_mut!(s => s.set_bootnode_config(enabled, &url)?)?;
            StorageWorkerResponse::Saved
        }
        StorageWorkerRequest::UserKeys(address) => {
            log::trace!("[{WORKER_NAME}] fetch user keys for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            if opt.is_some() {
                log::trace!(
                    "[{WORKER_NAME}] fetched notes and encryption keys for the account {address}"
                );
            } else {
                log::trace!(
                    "[{WORKER_NAME}] not found notes and encryption keys for the account {address}"
                );
            }
            StorageWorkerResponse::UserKeys(opt.map(|keys| UserKeys {
                note_keypair: PublicNoteKeyPair {
                    public: keys.note_keypair.public,
                },
                encryption_keypair: PublicEncryptionKeyPair {
                    public: keys.encryption_keypair.public,
                },
            }))
        }
        StorageWorkerRequest::AspSecret(address) => {
            log::trace!("[{WORKER_NAME}] fetch ASP secret for the account {address}");
            let opt = with_storage!(s => s.get_user_keys(&address)?)?;
            StorageWorkerResponse::AspSecret(opt.map(|keys| AspSecret {
                membership_blinding: keys.membership_blinding,
            }))
        }
        StorageWorkerRequest::UserNotes(address, limit) => {
            log::trace!("[{WORKER_NAME}] list user notes for the account {address}");
            let list = with_storage!(s => s.list_user_notes(&address, limit)?)?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} notes for the account {address}",
                list.len()
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::UnspentUserNotes {
            user_address,
            pool_contract_id,
        } => {
            log::trace!(
                "[{WORKER_NAME}] list all unspent notes for the account {user_address} in pool {pool_contract_id}"
            );
            let list = with_storage!(s =>
                s.list_unspent_user_notes(&pool_contract_id, &user_address)?
            )?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} unspent notes for the account {user_address}",
                list.len()
            );
            StorageWorkerResponse::UserNotes(list)
        }
        StorageWorkerRequest::RecentPoolActivity(limit) => {
            log::trace!("[{WORKER_NAME}] fetch recent pool activity");
            let list = with_storage!(s => s.get_recent_pool_activity(limit)?)?;
            log::trace!("[{WORKER_NAME}] fetched {} pool activity rows", list.len());
            StorageWorkerResponse::RecentPoolActivity(list)
        }
        StorageWorkerRequest::RecentPubKeys(limit) => {
            log::trace!("[{WORKER_NAME}] fetch pub keys for the address book");
            let list = with_storage!(s => s.get_recent_public_keys(limit)?)?;
            log::trace!(
                "[{WORKER_NAME}] fetched {} pub keys for the address book",
                list.len()
            );
            StorageWorkerResponse::PubKeys(list)
        }
        StorageWorkerRequest::DisclosureInputs(req) => {
            log::trace!(
                "[{WORKER_NAME}] build selective disclosure inputs for {}",
                req.user_address
            );

            let pool_root = req
                .pool_root
                .ok_or_else(|| anyhow::anyhow!("missing pool_root"))?;
            let (note_privkey, _note_pubkey, _encryption_pubkey, _membership_blinding) =
                load_user_key_material(&req.user_address)?;

            let tree = match build_validated_pool_tree(
                &req.pool_address,
                req.pool_next_index,
                req.tree_depth,
                pool_root,
            )? {
                Ok(tree) => tree,
                Err(status) => return Ok(StorageWorkerResponse::AspMembershipSync(status)),
            };

            let (amount, blinding, leaf_index) = with_storage!(
                s => s.get_unspent_user_note_by_commitment(&req.pool_address, &req.user_address, &req.selected_commitment)?
            )?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "unspent note not found for commitment {}",
                    req.selected_commitment
                )
            })?;

            let MerkleProof {
                path_elements,
                path_indices,
                root,
                ..
            } = tree.proof(leaf_index)?;

            StorageWorkerResponse::DisclosureInputs(DisclosureInputs {
                root,
                note_commitment: req.selected_commitment,
                note_amount: amount,
                note_private_key: note_privkey,
                note_blinding: blinding,
                merkle_path_indices: path_indices,
                merkle_path_elements: path_elements,
            })
        }
        StorageWorkerRequest::DeriveASPleaf(AdminASPRequest {
            membership_blinding,
            pubkey,
        }) => {
            log::trace!("[{WORKER_NAME}] derive user leaf from the pubkey for the admin");
            let user_leaf = asp_membership_leaf(&pubkey, &membership_blinding)?;
            log::trace!("[{WORKER_NAME}] derived user leaf from the pubkey for the admin");
            StorageWorkerResponse::DeriveASPleaf(user_leaf)
        }
        StorageWorkerRequest::Transact(req) => {
            log::trace!("[{WORKER_NAME}] transact");

            if req.input_commitments.len() > 2 {
                return Ok(StorageWorkerResponse::Error(
                    "transact input_commitments must have length 0..=2".to_string(),
                ));
            }

            let (note_privkey, note_pubkey, encryption_pubkey, membership_blinding) =
                load_user_key_material(&req.user_address)?;

            let membership_proof = match build_membership_proof(
                &req.aspmem_contract_id,
                &note_pubkey,
                membership_blinding,
                req.aspmem_root,
                req.aspmem_ledger,
                req.tree_depth,
            )? {
                Ok(p) => p,
                Err(status) => return Ok(StorageWorkerResponse::AspMembershipSync(status)),
            };

            let pool_root = req
                .pool_root
                .ok_or_else(|| anyhow::anyhow!("missing pool_root"))?;

            let inputs = match build_pool_inputs(
                &req.user_address,
                &req.pool_address,
                req.pool_next_index,
                req.tree_depth,
                pool_root,
                &req.input_commitments,
            )? {
                Ok(v) => v,
                Err(status) => return Ok(StorageWorkerResponse::AspMembershipSync(status)),
            };

            let mut outputs = Vec::with_capacity(N_OUTPUTS);
            for i in 0..N_OUTPUTS {
                let note_pk = req.out_recipient_note_pubkeys[i].clone();
                let enc_pk = req.out_recipient_encryption_pubkeys[i].clone();
                if note_pk.is_some() != enc_pk.is_some() {
                    return Ok(StorageWorkerResponse::Error(format!(
                        "output {i}: recipient_note_pubkey and recipient_encryption_pubkey must both be set or both be null"
                    )));
                }
                outputs.push(TransactOutput {
                    amount: req.output_amounts[i],
                    blinding: generate_random_blinding()?,
                    recipient_note_pubkey: note_pk,
                    recipient_encryption_pubkey: enc_pk,
                });
            }

            let params = TransactParams {
                priv_key: note_privkey,
                encryption_pubkey,
                pool_root,
                ext_recipient: req.ext_recipient,
                ext_amount: req.ext_amount,
                inputs,
                outputs,
                membership_proof,
                non_membership_proof: req.non_membership_proof,
                tree_depth: req.tree_depth,
                smt_depth: req.smt_depth,
            };

            StorageWorkerResponse::TransactParams(params)
        }
    };
    Ok(resp)
}

fn load_user_key_material(
    user_address: &str,
) -> Result<(
    types::NotePrivateKey,
    NotePublicKey,
    types::EncryptionPublicKey,
    Field,
)> {
    with_storage!(s => {
        let (note_privkey, note_pubkey, encryption_pubkey, membership_blinding) =
            match s.get_user_keys(user_address)? {
                Some(StoredUserKeys {
                    note_keypair:
                        NoteKeyPair {
                            private,
                            public: note_pub,
                        },
                    encryption_keypair: EncryptionKeyPair { public: enc_pub, .. },
                    membership_blinding,
                }) => (private, note_pub, enc_pub, membership_blinding),
                None => {
                    anyhow::bail!(
                        "address {user_address} should generate privacy keys and ASP secret first"
                    );
                }
            };
        Ok::<_, anyhow::Error>((
            note_privkey,
            note_pubkey,
            encryption_pubkey,
            membership_blinding,
        ))
    })?
}

fn build_membership_proof(
    aspmem_contract_id: &str,
    note_pubkey: &NotePublicKey,
    membership_blinding: Field,
    aspmem_root: Field,
    aspmem_ledger: u32,
    tree_depth: u32,
) -> Result<std::result::Result<AspMembershipProof, AspMembershipSync>> {
    let user_leaf = asp_membership_leaf(note_pubkey, &membership_blinding)?;
    let user_leaf_index = match with_storage!(s => s.check_asp_membership_precondition(
        aspmem_contract_id,
        &user_leaf,
        &aspmem_root,
        aspmem_ledger
    )?)? {
        AspMembershipSync::UserIndex(user_leaf_index) => user_leaf_index,
        status => {
            log::debug!("[{WORKER_NAME}] asp membership check is not fully synced");
            return Ok(Err(status));
        }
    };

    let asp_membership_merkle_tree_leaves =
        with_storage!(s => s.get_all_asp_membership_leaves_ordered(aspmem_contract_id)?)?;
    let aspmembership_tree =
        MerklePrefixTree::new(tree_depth, &asp_membership_merkle_tree_leaves)?.into_built();
    let MerkleProof {
        path_indices,
        path_elements,
        root,
        ..
    } = aspmembership_tree.proof(user_leaf_index)?;

    Ok(Ok(AspMembershipProof {
        leaf: user_leaf,
        blinding: membership_blinding,
        path_elements,
        path_indices,
        root,
    }))
}

fn build_pool_inputs(
    user_address: &str,
    pool_address: &str,
    pool_next_index: u32,
    tree_depth: u32,
    expected_pool_root: Field,
    input_commitments: &[Field],
) -> Result<std::result::Result<Vec<TransactInputNote>, AspMembershipSync>> {
    if input_commitments.is_empty() {
        return Ok(Ok(Vec::new()));
    }

    let tree = match build_validated_pool_tree(
        pool_address,
        pool_next_index,
        tree_depth,
        expected_pool_root,
    )? {
        Ok(tree) => tree,
        Err(status) => return Ok(Err(status)),
    };

    let mut out = Vec::with_capacity(input_commitments.len());
    for commitment in input_commitments {
        let Some((amount, blinding, leaf_index)) = with_storage!(s => s.get_unspent_user_note_by_commitment(pool_address, user_address, commitment)?)?
        else {
            log::info!(
                "[{WORKER_NAME}] unspent note not found for commitment {commitment}; waiting for note derivation"
            );
            return Ok(Err(AspMembershipSync::SyncRequired(None)));
        };

        out.push(build_pool_input_note(amount, blinding, leaf_index, &tree)?);
    }

    Ok(Ok(out))
}

fn build_validated_pool_tree(
    pool_address: &str,
    pool_next_index: u32,
    tree_depth: u32,
    expected_pool_root: Field,
) -> Result<std::result::Result<MerklePrefixTreeBuilt, AspMembershipSync>> {
    let leaves = with_storage!(s => s.get_pool_commitment_leaves_ordered(pool_address)?)?;

    if leaves.len() != pool_next_index as usize {
        log::info!(
            "[{WORKER_NAME}] pool commitments not synced: local={}, chain={}",
            leaves.len(),
            pool_next_index
        );
        return Ok(Err(AspMembershipSync::SyncRequired(None)));
    }

    let tree = MerklePrefixTree::new(tree_depth, &leaves)?.into_built();
    let computed_root = tree.root()?;
    if computed_root != expected_pool_root {
        anyhow::bail!("pool root mismatch: local computed root does not match on-chain root");
    }

    Ok(Ok(tree))
}

fn build_pool_input_note(
    amount: NoteAmount,
    blinding: Field,
    leaf_index: u32,
    tree: &MerklePrefixTreeBuilt,
) -> Result<TransactInputNote> {
    let MerkleProof {
        path_elements,
        path_indices,
        ..
    } = tree.proof(leaf_index)?;

    Ok(TransactInputNote {
        amount,
        blinding,
        merkle_path_elements: path_elements,
        merkle_path_indices: path_indices,
    })
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
