use crate::{
    protocol::{
        AdminASPRequest, DepositPrepared, DepositRequest, PreparedProverTx, ProverWorkerRequest,
        ProverWorkerResponse, StorageWorkerRequest, StorageWorkerResponse, TransactRequest,
        TransferRequest, WithdrawRequest,
    },
    workers::{prover::ProverWorker, storage::StorageWorker},
};
use anyhow::anyhow;
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{Spawnable, oneshot::OneshotBridge};
use js_sys::{Array, BigInt, Function, Object, Reflect};
use prover::{
    encryption::{ENCRYPTION_MESSAGE, SPENDING_KEY_MESSAGE},
    flows::N_OUTPUTS,
};
use std::{rc::Rc, str::FromStr};
use stellar::StateFetcher as CoreStateFetcher;
use types::{
    AspMembershipSync, EncryptionPublicKey, EncryptionSignature, ExtAmount, Field, NoteAmount,
    NotePublicKey, SMT_DEPTH, SpendingSignature,
};
use wasm_bindgen::{JsCast, prelude::*};

fn emit_progress(
    on_status: &Option<Function>,
    flow: &'static str,
    stage: &'static str,
    message: impl AsRef<str>,
    current: Option<u32>,
    total: Option<u32>,
) {
    let Some(cb) = on_status else { return };

    let obj = Object::new();
    let _ = Reflect::set(&obj, &JsValue::from_str("flow"), &JsValue::from_str(flow));
    let _ = Reflect::set(&obj, &JsValue::from_str("stage"), &JsValue::from_str(stage));
    let _ = Reflect::set(
        &obj,
        &JsValue::from_str("message"),
        &JsValue::from_str(message.as_ref()),
    );
    if let Some(current) = current {
        let _ = Reflect::set(
            &obj,
            &JsValue::from_str("current"),
            &JsValue::from_f64(current as f64),
        );
    }
    if let Some(total) = total {
        let _ = Reflect::set(
            &obj,
            &JsValue::from_str("total"),
            &JsValue::from_f64(total as f64),
        );
    }

    // Best-effort progress: never fail the transaction flow due to UI callbacks.
    if cb.call1(&JsValue::NULL, &obj.into()).is_err() {
        log::debug!("[WEBCLIENT] progress callback threw (flow={flow}, stage={stage})");
    }
}

#[wasm_bindgen]
pub struct WebClient {
    storage_bridge: OneshotBridge<StorageWorker>,
    prover_bridge: OneshotBridge<ProverWorker>,
    fetcher: Rc<CoreStateFetcher>,
}

impl Clone for WebClient {
    fn clone(&self) -> Self {
        Self {
            storage_bridge: self.storage_bridge.fork(),
            prover_bridge: self.prover_bridge.fork(),
            fetcher: self.fetcher.clone(),
        }
    }
}

async fn with_timeout<T>(ms: u32, fut: impl std::future::Future<Output = T>) -> anyhow::Result<T> {
    let fut = fut.fuse();
    let timeout = TimeoutFuture::new(ms).fuse();

    futures::pin_mut!(fut, timeout);

    futures::select! {
        value = fut => Ok(value),
        _ = timeout => Err(anyhow!("operation timed out after {} ms", ms)),
    }
}

impl WebClient {
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            storage_bridge: StorageWorker::spawner().spawn("./js/storage-worker.js"),
            prover_bridge: ProverWorker::spawner().spawn("./js/prover-worker.js"),
            fetcher: Rc::new(CoreStateFetcher::new(rpc_url)?),
        })
    }

    pub async fn ping_storage(&self) -> anyhow::Result<()> {
        let mut bridge = self.storage_bridge.fork();
        let resp = with_timeout(5_000, bridge.run(StorageWorkerRequest::Ping)).await?;
        match resp {
            StorageWorkerResponse::Pong => Ok(()),
            StorageWorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!(
                "unexpected response from Storage Worker: {:?}",
                other
            )),
        }
    }

    pub async fn ping_prover(&self) -> anyhow::Result<()> {
        let mut bridge = self.prover_bridge.fork();
        let resp = with_timeout(5_000, bridge.run(ProverWorkerRequest::Ping)).await?;
        match resp {
            ProverWorkerResponse::Pong => Ok(()),
            ProverWorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!(
                "unexpected response from Prover Worker: {:?}",
                other
            )),
        }
    }

    async fn storage_request(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsError> {
        let mut bridge = self.storage_bridge.fork();

        // Handle transport/timeout errors
        let resp: StorageWorkerResponse = with_timeout(timeout_ms, bridge.run(req))
            .await
            .map_err(|e| JsError::new(&format!("Storage Worker Communication Error: {}", e)))?;

        match resp {
            StorageWorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Ok(resp),
        }
    }

    async fn prover_request(
        &self,
        req: ProverWorkerRequest,
        timeout_ms: u32,
    ) -> Result<ProverWorkerResponse, JsError> {
        let mut bridge = self.prover_bridge.fork();

        // Handle transport/timeout errors
        let resp: ProverWorkerResponse = with_timeout(timeout_ms, bridge.run(req))
            .await
            .map_err(|e| JsError::new(&format!("Prover Worker Communication Error: {}", e)))?;

        match resp {
            ProverWorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Ok(resp),
        }
    }

    async fn prove_deposit_inner(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        amount_stroops: BigInt,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<Option<DepositPrepared>, JsError> {
        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;

        let amount_stroops = parse_ext_amount_decimal(&amount_stroops)?;
        if amount_stroops.as_i128() <= 0 {
            return Err(JsError::new("amount_stroops must be > 0 for deposit"));
        }

        emit_progress(
            &on_status,
            "deposit",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for (i, out) in out_amounts.iter_mut().enumerate().take(N_OUTPUTS) {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            *out = parse_note_amount_decimal(&bi)?;
        }

        let params = loop {
            emit_progress(
                &on_status,
                "deposit",
                "fetch_chain_state",
                "Fetching on-chain state…",
                None,
                None,
            );
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;

            emit_progress(
                &on_status,
                "deposit",
                "load_state",
                "Loading local keys…",
                None,
                None,
            );
            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

            emit_progress(
                &on_status,
                "deposit",
                "fetch_chain_state",
                "Fetching ASP non-membership proof…",
                None,
                None,
            );
            let non_membership_proof = self
                .fetcher
                .get_nonmembership_proof(
                    &note_pubkey,
                    data.asp_non_membership.root,
                    SMT_DEPTH as usize,
                    &user_address,
                )
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let req = DepositRequest {
                user_address: user_address.clone(),
                membership_blinding,
                amount_stroops,
                pool_root,
                pool_address: data.pool.contract_id,
                aspmem_root: data.asp_membership.root,
                aspmem_ledger: data.asp_membership.ledger,
                output_amounts: out_amounts,
                smt_depth: SMT_DEPTH,
                tree_depth: data.pool.merkle_levels,
                non_membership_proof,
            };

            emit_progress(
                &on_status,
                "deposit",
                "load_state",
                "Building witness inputs…",
                None,
                None,
            );
            match self
                .storage_request(StorageWorkerRequest::Deposit(req), 5_000)
                .await?
            {
                StorageWorkerResponse::DepositParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[DEPOSIT] the account {user_address} should register within ASP");
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[DEPOSIT] sync is needed - waiting the indexer");
                    emit_progress(
                        &on_status,
                        "deposit",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting for sync {gap} ledgers from the chain...")
                        } else {
                            "Waiting for sync ledgers from the chain...".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )));
                }
            }
        };

        emit_progress(&on_status, "deposit", "prove", "Proving…", None, None);
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Deposit(params), 20_000)
            .await?
        {
            ProverWorkerResponse::DepositPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(prepared))
    }

    async fn prove_withdraw_inner(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        withdraw_recipient: String,
        input_note_ids: Array,
        on_status: Option<Function>,
    ) -> Result<Option<PreparedProverTx>, JsError> {
        if input_note_ids.length() == 0 || input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 1..=2"));
        }

        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;

        emit_progress(
            &on_status,
            "withdraw",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        let mut input_commitments: Vec<Field> =
            Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_str(&s)?);
        }

        let params = loop {
            emit_progress(
                &on_status,
                "withdraw",
                "fetch_chain_state",
                "Fetching on-chain state…",
                None,
                None,
            );
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index =
                parse_u32_decimal(&data.pool.merkle_next_index).map_err(|e| JsError::new(&e))?;

            emit_progress(
                &on_status,
                "withdraw",
                "load_state",
                "Loading local keys…",
                None,
                None,
            );
            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

            emit_progress(
                &on_status,
                "withdraw",
                "fetch_chain_state",
                "Fetching ASP non-membership proof…",
                None,
                None,
            );
            let non_membership_proof = self
                .fetcher
                .get_nonmembership_proof(
                    &note_pubkey,
                    data.asp_non_membership.root,
                    SMT_DEPTH as usize,
                    &user_address,
                )
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let req = WithdrawRequest {
                user_address: user_address.clone(),
                membership_blinding,
                withdraw_recipient: withdraw_recipient.clone(),
                pool_root,
                pool_next_index,
                aspmem_root: data.asp_membership.root,
                aspmem_ledger: data.asp_membership.ledger,
                input_commitments: input_commitments.clone(),
                smt_depth: SMT_DEPTH,
                tree_depth: data.pool.merkle_levels,
                non_membership_proof,
            };

            emit_progress(
                &on_status,
                "withdraw",
                "load_state",
                "Building witness inputs…",
                None,
                None,
            );
            match self
                .storage_request(StorageWorkerRequest::Withdraw(req), 5_000)
                .await?
            {
                StorageWorkerResponse::WithdrawParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[WITHDRAW] the account {user_address} should register within ASP");
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[WITHDRAW] sync is needed - waiting the indexer");
                    emit_progress(
                        &on_status,
                        "withdraw",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting for sync {gap} ledgers from the chain...")
                        } else {
                            "Waiting for sync ledgers from the chain...".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )));
                }
            }
        };

        emit_progress(&on_status, "withdraw", "prove", "Proving…", None, None);
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Withdraw(params), 20_000)
            .await?
        {
            ProverWorkerResponse::WithdrawPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(prepared))
    }

    #[allow(clippy::too_many_arguments)]
    async fn prove_transfer_inner(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        recipient_note_key_hex: String,
        recipient_enc_key_hex: String,
        input_note_ids: Array,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<Option<PreparedProverTx>, JsError> {
        if input_note_ids.length() == 0 || input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 1..=2"));
        }
        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;

        emit_progress(
            &on_status,
            "transfer",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        let recipient_note_pubkey = NotePublicKey::parse(&recipient_note_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let recipient_enc_pubkey = EncryptionPublicKey::parse(&recipient_enc_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let mut input_commitments: Vec<Field> =
            Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_str(&s)?);
        }

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for (i, out) in out_amounts.iter_mut().enumerate().take(N_OUTPUTS) {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            *out = parse_note_amount_decimal(&bi)?;
        }

        let params = loop {
            emit_progress(
                &on_status,
                "transfer",
                "fetch_chain_state",
                "Fetching on-chain state…",
                None,
                None,
            );
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index =
                parse_u32_decimal(&data.pool.merkle_next_index).map_err(|e| JsError::new(&e))?;

            emit_progress(
                &on_status,
                "transfer",
                "load_state",
                "Loading local keys…",
                None,
                None,
            );
            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

            emit_progress(
                &on_status,
                "transfer",
                "fetch_chain_state",
                "Fetching ASP non-membership proof…",
                None,
                None,
            );
            let non_membership_proof = self
                .fetcher
                .get_nonmembership_proof(
                    &note_pubkey,
                    data.asp_non_membership.root,
                    SMT_DEPTH as usize,
                    &user_address,
                )
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let req = TransferRequest {
                user_address: user_address.clone(),
                membership_blinding,
                pool_root,
                pool_next_index,
                pool_address: data.pool.contract_id,
                aspmem_root: data.asp_membership.root,
                aspmem_ledger: data.asp_membership.ledger,
                input_commitments: input_commitments.clone(),
                output_amounts: out_amounts,
                recipient_note_pubkey: recipient_note_pubkey.clone(),
                recipient_encryption_pubkey: recipient_enc_pubkey.clone(),
                smt_depth: SMT_DEPTH,
                tree_depth: data.pool.merkle_levels,
                non_membership_proof,
            };

            emit_progress(
                &on_status,
                "transfer",
                "load_state",
                "Building witness inputs…",
                None,
                None,
            );
            match self
                .storage_request(StorageWorkerRequest::Transfer(req), 5_000)
                .await?
            {
                StorageWorkerResponse::TransferParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[TRANSFER] the account {user_address} should register within ASP");
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[TRANSFER] sync is needed - waiting the indexer");
                    emit_progress(
                        &on_status,
                        "transfer",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting for sync {gap} ledgers from the chain...")
                        } else {
                            "Waiting for sync ledgers from the chain...".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )));
                }
            }
        };

        emit_progress(&on_status, "transfer", "prove", "Proving…", None, None);
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Transfer(params), 20_000)
            .await?
        {
            ProverWorkerResponse::TransferPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(prepared))
    }

    #[allow(clippy::too_many_arguments)]
    async fn prove_transact_inner(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        ext_recipient: String,
        ext_amount_stroops: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        on_status: Option<Function>,
    ) -> Result<Option<PreparedProverTx>, JsError> {
        if input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 0..=2"));
        }
        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }
        if out_recipient_note_keys_hex.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "out_recipient_note_keys_hex must have length {N_OUTPUTS}"
            )));
        }
        if out_recipient_enc_keys_hex.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "out_recipient_enc_keys_hex must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;
        let ext_amount = parse_ext_amount_decimal(&ext_amount_stroops)?;

        emit_progress(
            &on_status,
            "transact",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        let mut input_commitments: Vec<Field> =
            Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_str(&s)?);
        }

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for (i, out) in out_amounts.iter_mut().enumerate().take(N_OUTPUTS) {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            *out = parse_note_amount_decimal(&bi)?;
        }

        let mut out_note_pks: [Option<NotePublicKey>; N_OUTPUTS] = [None, None];
        let mut out_enc_pks: [Option<EncryptionPublicKey>; N_OUTPUTS] = [None, None];
        for i in 0..N_OUTPUTS {
            let nk = out_recipient_note_keys_hex.get(i as u32);
            let ek = out_recipient_enc_keys_hex.get(i as u32);

            let note_pk = if nk.is_null() || nk.is_undefined() {
                None
            } else {
                let s = nk.as_string().ok_or_else(|| {
                    JsError::new("out_recipient_note_keys_hex must be (string|null)[]")
                })?;
                Some(NotePublicKey::parse(&s).map_err(|e| JsError::new(&e.to_string()))?)
            };

            let enc_pk = if ek.is_null() || ek.is_undefined() {
                None
            } else {
                let s = ek.as_string().ok_or_else(|| {
                    JsError::new("out_recipient_enc_keys_hex must be (string|null)[]")
                })?;
                Some(EncryptionPublicKey::parse(&s).map_err(|e| JsError::new(&e.to_string()))?)
            };

            out_note_pks[i] = note_pk;
            out_enc_pks[i] = enc_pk;
        }

        let params = loop {
            emit_progress(
                &on_status,
                "transact",
                "fetch_chain_state",
                "Fetching on-chain state…",
                None,
                None,
            );
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index =
                parse_u32_decimal(&data.pool.merkle_next_index).map_err(|e| JsError::new(&e))?;

            emit_progress(
                &on_status,
                "transact",
                "load_state",
                "Loading local keys…",
                None,
                None,
            );
            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

            emit_progress(
                &on_status,
                "transact",
                "fetch_chain_state",
                "Fetching ASP non-membership proof…",
                None,
                None,
            );
            let non_membership_proof = self
                .fetcher
                .get_nonmembership_proof(
                    &note_pubkey,
                    data.asp_non_membership.root,
                    SMT_DEPTH as usize,
                    &user_address,
                )
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let req = TransactRequest {
                user_address: user_address.clone(),
                membership_blinding,
                pool_root,
                pool_next_index,
                pool_address: data.pool.contract_id,
                ext_recipient: ext_recipient.clone(),
                ext_amount,
                aspmem_root: data.asp_membership.root,
                aspmem_ledger: data.asp_membership.ledger,
                input_commitments: input_commitments.clone(),
                output_amounts: out_amounts,
                out_recipient_note_pubkeys: out_note_pks.clone(),
                out_recipient_encryption_pubkeys: out_enc_pks.clone(),
                smt_depth: SMT_DEPTH,
                tree_depth: data.pool.merkle_levels,
                non_membership_proof,
            };

            emit_progress(
                &on_status,
                "transact",
                "load_state",
                "Building witness inputs…",
                None,
                None,
            );
            match self
                .storage_request(StorageWorkerRequest::Transact(req), 5_000)
                .await?
            {
                StorageWorkerResponse::TransactParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[TRANSACT] the account {user_address} should register within ASP");
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[TRANSACT] sync is needed - waiting the indexer");
                    emit_progress(
                        &on_status,
                        "transact",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting for sync {gap} ledgers from the chain...")
                        } else {
                            "Waiting for sync ledgers from the chain...".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )));
                }
            }
        };

        emit_progress(&on_status, "transact", "prove", "Proving…", None, None);
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Transact(params), 20_000)
            .await?
        {
            ProverWorkerResponse::TransactPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(prepared))
    }
}

#[wasm_bindgen]
impl WebClient {
    #[wasm_bindgen(js_name = poolContractState)]
    pub async fn pool_contract_state(&self) -> Result<JsValue, JsError> {
        let pool_info = self
            .fetcher
            .pool_contract_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&pool_info)?)
    }

    #[wasm_bindgen(js_name = aspMembershipContractState)]
    pub async fn asp_membership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_membership = self
            .fetcher
            .asp_membership_contract_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_membership)?)
    }

    #[wasm_bindgen(js_name = aspNonmembershipContractState)]
    pub async fn asp_nonmembership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_nonmembership = self
            .fetcher
            .asp_nonmembership_contract_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_nonmembership)?)
    }

    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self
            .fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config(&self) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(
            self.fetcher.contract_config(),
        )?)
    }

    #[wasm_bindgen(js_name = encryptionDerivationMessage)]
    pub fn encryption_derivation_message(&self) -> String {
        ENCRYPTION_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = spendingKeyMessage)]
    pub fn spending_key_message(&self) -> String {
        SPENDING_KEY_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = deriveAndSaveUserKeys)]
    pub async fn derive_save_user_keys(
        &self,
        address: String,
        spending_sig: Vec<u8>,
        encryption_sig: Vec<u8>,
    ) -> Result<(), JsError> {
        let req = StorageWorkerRequest::DeriveSaveUserKeys(
            address,
            SpendingSignature(spending_sig),
            EncryptionSignature(encryption_sig),
        );

        match self.storage_request(req, 5_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getDisclaimerState)]
    pub async fn get_disclaimer_state(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::DisclaimerState(address);
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::DisclaimerState(state) => {
                Ok(serde_wasm_bindgen::to_value(&state)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = acceptDisclaimer)]
    pub async fn accept_disclaimer(
        &self,
        address: String,
        disclaimer_hash_hex: String,
    ) -> Result<(), JsError> {
        let req = StorageWorkerRequest::AcceptDisclaimer(address, disclaimer_hash_hex);
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserKeys)]
    pub async fn get_user_keys(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::UserKeys(address);

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = deriveAspUserLeaf)]
    pub async fn derive_asp_user_leaf(
        &self,
        membership_blinding_hex_be: &str,
        pubkey_hex: &str,
    ) -> Result<JsValue, JsError> {
        let membership_blinding = Field::from_str(membership_blinding_hex_be)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let pubkey_deserializer =
            serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(pubkey_hex);
        let pubkey: NotePublicKey =
            <NotePublicKey as serde::Deserialize>::deserialize(pubkey_deserializer)
                .map_err(|e| JsError::new(&format!("invalid pubkey_hex: {e}")))?;

        let req = StorageWorkerRequest::DeriveASPleaf(AdminASPRequest {
            membership_blinding,
            pubkey,
        });

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::DeriveASPleaf(user_leaf) => {
                Ok(serde_wasm_bindgen::to_value(&user_leaf)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getRecentPublicKeys)]
    pub async fn get_recent_public_keys(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::RecentPubKeys(limit);

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::PubKeys(list) => Ok(serde_wasm_bindgen::to_value(&list)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserNotes)]
    pub async fn get_user_notes(&self, address: String, limit: u32) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::UserNotes(address, limit);
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::UserNotes(list) => Ok(serde_wasm_bindgen::to_value(&list)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getRecentPoolActivity)]
    pub async fn get_recent_pool_activity(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::RecentPoolActivity(limit);
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::RecentPoolActivity(list) => {
                Ok(serde_wasm_bindgen::to_value(&list)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = proveDeposit)]
    pub async fn prove_deposit(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        amount_stroops: BigInt,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let prepared = self
            .prove_deposit_inner(
                user_address,
                membership_blinding,
                amount_stroops,
                output_amounts,
                on_status,
            )
            .await?;
        match prepared {
            None => Ok(JsValue::NULL),
            Some(p) => Ok(serde_wasm_bindgen::to_value(&p)?),
        }
    }

    #[wasm_bindgen(js_name = proveWithdraw)]
    pub async fn prove_withdraw(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        withdraw_recipient: String,
        input_note_ids: Array,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let prepared = self
            .prove_withdraw_inner(
                user_address,
                membership_blinding,
                withdraw_recipient,
                input_note_ids,
                on_status,
            )
            .await?;
        match prepared {
            None => Ok(JsValue::NULL),
            Some(p) => Ok(serde_wasm_bindgen::to_value(&p)?),
        }
    }

    #[wasm_bindgen(js_name = proveTransfer)]
    #[allow(clippy::too_many_arguments)]
    pub async fn prove_transfer(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        recipient_note_key_hex: String,
        recipient_enc_key_hex: String,
        input_note_ids: Array,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let prepared = self
            .prove_transfer_inner(
                user_address,
                membership_blinding,
                recipient_note_key_hex,
                recipient_enc_key_hex,
                input_note_ids,
                output_amounts,
                on_status,
            )
            .await?;
        match prepared {
            None => Ok(JsValue::NULL),
            Some(p) => Ok(serde_wasm_bindgen::to_value(&p)?),
        }
    }

    #[wasm_bindgen(js_name = proveTransact)]
    #[allow(clippy::too_many_arguments)]
    pub async fn prove_transact(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        ext_recipient: String,
        ext_amount_stroops: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let prepared = self
            .prove_transact_inner(
                user_address,
                membership_blinding,
                ext_recipient,
                ext_amount_stroops,
                input_note_ids,
                output_amounts,
                out_recipient_note_keys_hex,
                out_recipient_enc_keys_hex,
                on_status,
            )
            .await?;
        match prepared {
            None => Ok(JsValue::NULL),
            Some(p) => Ok(serde_wasm_bindgen::to_value(&p)?),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for WebClient {
    async fn get_sync_state(&self) -> anyhow::Result<Option<types::SyncMetadata>> {
        let mut bridge = self.storage_bridge.fork();
        let resp = with_timeout(5_000, bridge.run(StorageWorkerRequest::SyncState)).await?;
        match resp {
            StorageWorkerResponse::SyncState(state) => Ok(state),
            StorageWorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }

    async fn save_events_batch(&self, data: types::ContractsEventData) -> anyhow::Result<()> {
        let mut bridge = self.storage_bridge.fork();
        let resp = with_timeout(10_000, bridge.run(StorageWorkerRequest::SaveEvents(data))).await?;
        match resp {
            StorageWorkerResponse::Saved => Ok(()),
            StorageWorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }
}

fn parse_field_bigint_numeric(b: &BigInt) -> Result<Field, JsError> {
    let hex = bigint_to_string_radix(b, 16)?;
    if hex.starts_with('-') {
        return Err(JsError::new("field BigInt must be non-negative"));
    }
    if hex.len() > 64 {
        return Err(JsError::new("field BigInt does not fit into 256 bits"));
    }
    let padded = format!("{hex:0>64}");
    let s = format!("0x{padded}");
    Field::from_0x_hex_be(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn bigint_to_string_radix(b: &BigInt, radix: u8) -> Result<String, JsError> {
    let js = b
        .to_string(radix)
        .map_err(|e| JsError::new(&format!("failed to stringify BigInt: {e:?}")))?;
    js.as_string()
        .ok_or_else(|| JsError::new("BigInt.toString() did not return a string"))
}

fn parse_ext_amount_decimal(b: &BigInt) -> Result<ExtAmount, JsError> {
    let s = bigint_to_string_radix(b, 10)?;
    ExtAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_note_amount_decimal(b: &BigInt) -> Result<NoteAmount, JsError> {
    let s = bigint_to_string_radix(b, 10)?;
    NoteAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_field_hex_str(s: &str) -> Result<Field, JsError> {
    let s = s.trim();
    let prefixed = if s.starts_with("0x") || s.starts_with("0X") {
        s.to_string()
    } else {
        format!("0x{s}")
    };
    Field::from_str(&prefixed).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_u32_decimal(s: &str) -> Result<u32, String> {
    let v: u64 = s
        .parse::<u64>()
        .map_err(|_| format!("invalid decimal u64: {s}"))?;
    u32::try_from(v).map_err(|_| format!("value does not fit into u32: {s}"))
}
