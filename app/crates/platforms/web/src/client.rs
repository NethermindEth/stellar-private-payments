use crate::workers::{prover::ProverWorker, storage::StorageWorker};
use stellar::{StateFetcher as CoreStateFetcher};
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use crate::protocol::{
    AdminASPRequest, DepositRequest, ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest,
    StorageWorkerResponse, TransactRequest, TransferRequest, WithdrawRequest,
};
use prover::encryption::{ENCRYPTION_MESSAGE, SPENDING_KEY_MESSAGE};
use prover::flows::N_OUTPUTS;
use types::{
    AspMembershipSync, EncryptionPublicKey, EncryptionSignature, ExtAmount, Field, NoteAmount,
    NotePublicKey, SpendingSignature, SMT_DEPTH,
};
use wasm_bindgen::prelude::*;
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use anyhow::anyhow;
use std::rc::Rc;
use std::str::FromStr;
use wasm_bindgen::JsCast;
use js_sys::{Array, BigInt};


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

async fn with_timeout<T>(
    ms: u32,
    fut: impl std::future::Future<Output = T>,
) -> anyhow::Result<T> {
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
            other => Err(anyhow::anyhow!("unexpected response from Storage Worker: {:?}", other)),
        }
    }

    pub async fn ping_prover(&self) -> anyhow::Result<()> {
        let mut bridge = self.prover_bridge.fork();
        let resp = with_timeout(5_000, bridge.run(ProverWorkerRequest::Ping)).await?;
        match resp {
            ProverWorkerResponse::Pong => Ok(()),
            ProverWorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response from Prover Worker: {:?}", other)),
        }
    }
}

#[wasm_bindgen]
impl WebClient {

    #[wasm_bindgen(js_name = poolContractState)]
    pub async fn pool_contract_state(&self) -> Result<JsValue, JsError> {
        let pool_info = self.fetcher.pool_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&pool_info)?)
    }

    #[wasm_bindgen(js_name = aspMembershipContractState)]
    pub async fn asp_membership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_membership = self.fetcher.asp_membership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_membership)?)
    }

    #[wasm_bindgen(js_name = aspNonmembershipContractState)]
    pub async fn asp_nonmembership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_nonmembership = self.fetcher.asp_nonmembership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_nonmembership)?)
    }

    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self.fetcher.all_contracts_data().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    #[wasm_bindgen(js_name = encryptionDerivationMessage)]
    pub fn encryption_derivation_message(&self) -> String {
        ENCRYPTION_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = spendingKeyMessage)]
    pub fn spending_key_message(&self) -> String {
        SPENDING_KEY_MESSAGE.to_string()
    }

    async fn storage_request(&self, req: StorageWorkerRequest, timeout_ms: u32) -> Result<StorageWorkerResponse, JsError> {
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

    async fn prover_request(&self, req: ProverWorkerRequest, timeout_ms: u32) -> Result<ProverWorkerResponse, JsError> {
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

    #[wasm_bindgen(js_name = deriveAndSaveUserKeys)]
    pub async fn derive_save_user_keys(&self, address: String, spending_sig: Vec<u8>, encryption_sig: Vec<u8>) -> Result<(), JsError> {
        let req = StorageWorkerRequest::DeriveSaveUserKeys(
            address,
            SpendingSignature(spending_sig),
            EncryptionSignature(encryption_sig)
        );

        match self.storage_request(req, 5_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserKeys)]
    pub async fn get_user_keys(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::UserKeys(
            address,
        );

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = deriveAspUserLeaf)]
    pub async fn derive_asp_user_leaf(&self, membership_blinding_hex_be: &str, pubkey_hex_le: &str) -> Result<JsValue, JsError> {
        let membership_blinding = Field::from_str(membership_blinding_hex_be).map_err(|e| JsError::new(&e.to_string()))?;

        let pubkey_deserializer =
            serde::de::value::BorrowedStrDeserializer::<serde::de::value::Error>::new(pubkey_hex_le);
        let pubkey: NotePublicKey = <NotePublicKey as serde::Deserialize>::deserialize(pubkey_deserializer)
            .map_err(|e| JsError::new(&format!("invalid pubkey_hex: {e}")))?;

        let req = StorageWorkerRequest::DeriveASPleaf(
            AdminASPRequest{
                membership_blinding,
                pubkey,
            }
        );

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::DeriveASPleaf(user_leaf) => Ok(serde_wasm_bindgen::to_value(&user_leaf)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getRecentPublicKeys)]
    pub async fn get_recent_public_keys(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::RecentPubKeys(
            limit,
        );

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::PubKeys(list) => Ok(serde_wasm_bindgen::to_value(&list)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = proveDepositPrepareTx)]
    pub async fn prove_deposit_prepare_tx(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        amount_stroops: BigInt,
        output_amounts: Array,
    ) -> Result<JsValue, JsError> {

        fn bigint_to_string(b: &BigInt) -> Result<String, JsError> {
            let js = b
                .to_string(10)
                .map_err(|e| JsError::new(&format!("failed to stringify BigInt: {e:?}")))?;
            js.as_string()
                .ok_or_else(|| JsError::new("BigInt.toString() did not return a string"))
        }

        fn parse_ext_amount_decimal(b: &BigInt) -> Result<ExtAmount, JsError> {
            let s = bigint_to_string(b)?;
            ExtAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
        }

        fn parse_note_amount_decimal(b: &BigInt) -> Result<NoteAmount, JsError> {
            let s = bigint_to_string(b)?;
            NoteAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
        }

        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_hex_be(&membership_blinding)?;

        let amount_stroops = parse_ext_amount_decimal(&amount_stroops)?;
        if amount_stroops.as_i128() <= 0 {
            return Err(JsError::new("amount_stroops must be > 0 for deposit"));
        }

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for i in 0..N_OUTPUTS {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            out_amounts[i] = parse_note_amount_decimal(&bi)?;
        }

        let params = loop {
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data
                .pool
                .merkle_root;

            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => keys
                    .ok_or_else(|| JsError::new("user keys not found in worker storage"))?,
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

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

            match self.storage_request(StorageWorkerRequest::Deposit(req), 5_000).await? {
                StorageWorkerResponse::DepositParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[DEPOSIT] the account {user_address} should register within ASP");
                    return Ok(JsValue::NULL);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired) => {
                    log::info!("[DEPOSIT] sync is needed - waiting the indexer");
                    gloo_timers::future::TimeoutFuture::new(1_000).await;
                    continue;
                },
                other => return Err(JsError::new(&format!("Unexpected storage worker response: {:?}", other))),
            }
        };

        self.ping_prover().await.map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self.prover_request(ProverWorkerRequest::Deposit(params), 5_000).await? {
            ProverWorkerResponse::DepositPrepared(p) => p,
            other => return Err(JsError::new(&format!("Unexpected prover worker response: {:?}", other))),
        };

        let public_inputs = stellar::OnchainProofPublicInputs {
            root: prepared.prepared.pool_root,
            input_nullifiers: prepared.prepared.input_nullifiers,
            output_commitment0: prepared.prepared.output_commitments[0],
            output_commitment1: prepared.prepared.output_commitments[1],
            public_amount: prepared.prepared.public_amount,
            ext_data_hash_be: prepared.prepared.ext_data_hash_be,
            asp_membership_root: prepared.prepared.asp_membership_root,
            asp_non_membership_root: prepared.prepared.asp_non_membership_root,
        };

        let tx = self
            .fetcher
            .prepare_pool_transact_tx(
                &user_address,
                &prepared.proof_uncompressed,
                &prepared.ext_data,
                &public_inputs,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&tx)?)
    }

    #[wasm_bindgen(js_name = proveWithdrawPrepareTx)]
    pub async fn prove_withdraw_prepare_tx(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        withdraw_recipient: String,
        input_note_ids: Array,
    ) -> Result<JsValue, JsError> {
        if input_note_ids.length() == 0 || input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 1..=2"));
        }

        let membership_blinding = parse_field_hex_be(&membership_blinding)?;

        let mut input_commitments: Vec<Field> = Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_be_str(&s)?);
        }

        let params = loop {
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index = parse_u32_decimal(&data.pool.merkle_next_index)
                .map_err(|e| JsError::new(&e))?;

            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => keys
                    .ok_or_else(|| JsError::new("user keys not found in worker storage"))?,
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

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

            match self.storage_request(StorageWorkerRequest::Withdraw(req), 5_000).await? {
                StorageWorkerResponse::WithdrawParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[WITHDRAW] the account {user_address} should register within ASP");
                    return Ok(JsValue::NULL);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired) => {
                    log::info!("[WITHDRAW] sync is needed - waiting the indexer");
                    gloo_timers::future::TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )))
                }
            }
        };

        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Withdraw(params), 5_000)
            .await?
        {
            ProverWorkerResponse::WithdrawPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )))
            }
        };

        let public_inputs = stellar::OnchainProofPublicInputs {
            root: prepared.prepared.pool_root,
            input_nullifiers: prepared.prepared.input_nullifiers,
            output_commitment0: prepared.prepared.output_commitments[0],
            output_commitment1: prepared.prepared.output_commitments[1],
            public_amount: prepared.prepared.public_amount,
            ext_data_hash_be: prepared.prepared.ext_data_hash_be,
            asp_membership_root: prepared.prepared.asp_membership_root,
            asp_non_membership_root: prepared.prepared.asp_non_membership_root,
        };

        let tx = self
            .fetcher
            .prepare_pool_transact_tx(
                &user_address,
                &prepared.proof_uncompressed,
                &prepared.ext_data,
                &public_inputs,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&tx)?)
    }

    #[wasm_bindgen(js_name = proveTransferPrepareTx)]
    pub async fn prove_transfer_prepare_tx(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        recipient_note_key_be_hex: String,
        recipient_enc_key_hex: String,
        input_note_ids: Array,
        output_amounts: Array,
    ) -> Result<JsValue, JsError> {
        if input_note_ids.length() == 0 || input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 1..=2"));
        }
        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_hex_be(&membership_blinding)?;

        let recipient_note_field = parse_field_hex_be_str(&recipient_note_key_be_hex)?;
        let recipient_note_pubkey = NotePublicKey(recipient_note_field.to_le_bytes());
        let recipient_enc_bytes = parse_hex_32(&recipient_enc_key_hex)?;
        let recipient_enc_pubkey = EncryptionPublicKey(recipient_enc_bytes);

        let mut input_commitments: Vec<Field> = Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_be_str(&s)?);
        }

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for i in 0..N_OUTPUTS {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            out_amounts[i] = parse_note_amount_decimal(&bi)?;
        }

        let params = loop {
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index = parse_u32_decimal(&data.pool.merkle_next_index)
                .map_err(|e| JsError::new(&e))?;

            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => keys
                    .ok_or_else(|| JsError::new("user keys not found in worker storage"))?,
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

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

            match self.storage_request(StorageWorkerRequest::Transfer(req), 5_000).await? {
                StorageWorkerResponse::TransferParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[TRANSFER] the account {user_address} should register within ASP");
                    return Ok(JsValue::NULL);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired) => {
                    log::info!("[TRANSFER] sync is needed - waiting the indexer");
                    gloo_timers::future::TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )))
                }
            }
        };

        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Transfer(params), 5_000)
            .await?
        {
            ProverWorkerResponse::TransferPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )))
            }
        };

        let public_inputs = stellar::OnchainProofPublicInputs {
            root: prepared.prepared.pool_root,
            input_nullifiers: prepared.prepared.input_nullifiers,
            output_commitment0: prepared.prepared.output_commitments[0],
            output_commitment1: prepared.prepared.output_commitments[1],
            public_amount: prepared.prepared.public_amount,
            ext_data_hash_be: prepared.prepared.ext_data_hash_be,
            asp_membership_root: prepared.prepared.asp_membership_root,
            asp_non_membership_root: prepared.prepared.asp_non_membership_root,
        };

        let tx = self
            .fetcher
            .prepare_pool_transact_tx(
                &user_address,
                &prepared.proof_uncompressed,
                &prepared.ext_data,
                &public_inputs,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&tx)?)
    }

    #[wasm_bindgen(js_name = proveTransactPrepareTx)]
    pub async fn prove_transact_prepare_tx(
        &self,
        user_address: String,
        membership_blinding: BigInt,
        ext_recipient: String,
        ext_amount_stroops: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_be_hex: Array,
        out_recipient_enc_keys_hex: Array,
    ) -> Result<JsValue, JsError> {
        if input_note_ids.length() > 2 {
            return Err(JsError::new("input_note_ids must have length 0..=2"));
        }
        if output_amounts.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "output_amounts must have length {N_OUTPUTS}"
            )));
        }
        if out_recipient_note_keys_be_hex.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "out_recipient_note_keys_be_hex must have length {N_OUTPUTS}"
            )));
        }
        if out_recipient_enc_keys_hex.length() != N_OUTPUTS as u32 {
            return Err(JsError::new(&format!(
                "out_recipient_enc_keys_hex must have length {N_OUTPUTS}"
            )));
        }

        let membership_blinding = parse_field_hex_be(&membership_blinding)?;
        let ext_amount = parse_ext_amount_decimal(&ext_amount_stroops)?;

        let mut input_commitments: Vec<Field> = Vec::with_capacity(input_note_ids.length() as usize);
        for i in 0..input_note_ids.length() {
            let v = input_note_ids.get(i);
            let s = v
                .as_string()
                .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
            input_commitments.push(parse_field_hex_be_str(&s)?);
        }

        let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
        for i in 0..N_OUTPUTS {
            let v = output_amounts.get(i as u32);
            let bi: BigInt = v
                .dyn_into()
                .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
            out_amounts[i] = parse_note_amount_decimal(&bi)?;
        }

        let mut out_note_pks: [Option<NotePublicKey>; N_OUTPUTS] = [None, None];
        let mut out_enc_pks: [Option<EncryptionPublicKey>; N_OUTPUTS] = [None, None];
        for i in 0..N_OUTPUTS {
            let nk = out_recipient_note_keys_be_hex.get(i as u32);
            let ek = out_recipient_enc_keys_hex.get(i as u32);

            let note_pk = if nk.is_null() || nk.is_undefined() {
                None
            } else {
                let s = nk
                    .as_string()
                    .ok_or_else(|| JsError::new("out_recipient_note_keys_be_hex must be (string|null)[]"))?;
                let f = parse_field_hex_be_str(&s)?;
                Some(NotePublicKey(f.to_le_bytes()))
            };

            let enc_pk = if ek.is_null() || ek.is_undefined() {
                None
            } else {
                let s = ek
                    .as_string()
                    .ok_or_else(|| JsError::new("out_recipient_enc_keys_hex must be (string|null)[]"))?;
                let b = parse_hex_32(&s)?;
                Some(EncryptionPublicKey(b))
            };

            out_note_pks[i] = note_pk;
            out_enc_pks[i] = enc_pk;
        }

        let params = loop {
            let data = self
                .fetcher
                .all_contracts_data()
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool_root = data.pool.merkle_root;
            let pool_next_index = parse_u32_decimal(&data.pool.merkle_next_index)
                .map_err(|e| JsError::new(&e))?;

            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => keys
                    .ok_or_else(|| JsError::new("user keys not found in worker storage"))?,
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

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

            match self.storage_request(StorageWorkerRequest::Transact(req), 5_000).await? {
                StorageWorkerResponse::TransactParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[TRANSACT] the account {user_address} should register within ASP");
                    return Ok(JsValue::NULL);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired) => {
                    log::info!("[TRANSACT] sync is needed - waiting the indexer");
                    gloo_timers::future::TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )))
                }
            }
        };

        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Transact(params), 5_000)
            .await?
        {
            ProverWorkerResponse::TransactPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )))
            }
        };

        let public_inputs = stellar::OnchainProofPublicInputs {
            root: prepared.prepared.pool_root,
            input_nullifiers: prepared.prepared.input_nullifiers,
            output_commitment0: prepared.prepared.output_commitments[0],
            output_commitment1: prepared.prepared.output_commitments[1],
            public_amount: prepared.prepared.public_amount,
            ext_data_hash_be: prepared.prepared.ext_data_hash_be,
            asp_membership_root: prepared.prepared.asp_membership_root,
            asp_non_membership_root: prepared.prepared.asp_non_membership_root,
        };

        let tx = self
            .fetcher
            .prepare_pool_transact_tx(
                &user_address,
                &prepared.proof_uncompressed,
                &prepared.ext_data,
                &public_inputs,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(serde_wasm_bindgen::to_value(&tx)?)
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

fn parse_field_hex_be(b: &BigInt) -> Result<Field, JsError> {
    let hex = bigint_to_string_radix(b, 16)?;
    if hex.starts_with('-') {
        return Err(JsError::new("field BigInt must be non-negative"));
    }
    if hex.len() > 64 {
        return Err(JsError::new("field BigInt does not fit into 256 bits"));
    }
    let padded = format!("{hex:0>64}");
    let s = format!("0x{padded}");
    Field::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn bigint_to_string_radix(b: &BigInt, radix: u8) -> Result<String, JsError> {
    let js = b
        .to_string(radix)
        .map_err(|e| JsError::new(&format!("failed to stringify BigInt: {e:?}")))?;
    js.as_string()
        .ok_or_else(|| JsError::new("BigInt.toString() did not return a string"))
}

fn parse_field_hex_be_str(s: &str) -> Result<Field, JsError> {
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

fn bigint_to_string_decimal(b: &BigInt) -> Result<String, JsError> {
    bigint_to_string_radix(b, 10)
}

fn parse_ext_amount_decimal(b: &BigInt) -> Result<ExtAmount, JsError> {
    let s = bigint_to_string_decimal(b)?;
    ExtAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_note_amount_decimal(b: &BigInt) -> Result<NoteAmount, JsError> {
    let s = bigint_to_string_decimal(b)?;
    NoteAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], JsError> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() != 64 {
        return Err(JsError::new("hex string must be 32 bytes (64 hex chars)"));
    }

    fn hex_val(b: u8) -> Result<u8, JsError> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(JsError::new("invalid hex character")),
        }
    }

    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}
