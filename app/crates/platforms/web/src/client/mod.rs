use crate::{
    protocol::{
        AdminASPRequest, ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest,
        StorageWorkerResponse,
    },
    workers::{prover::ProverWorker, storage::StorageWorker},
};
use anyhow::anyhow;
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{Spawnable, oneshot::OneshotBridge};
use js_sys::{Array, BigInt, Function, Object, Reflect};
use prover::{encryption::KEY_DERIVATION_MESSAGE, flows::N_OUTPUTS};
use std::{rc::Rc, str::FromStr};
use stellar::StateFetcher as CoreStateFetcher;
use types::{
    ContractConfig, EncryptionPublicKey, ExtAmount, Field, KeyDerivationSignature, NoteAmount,
    NotePublicKey,
};
use wasm_bindgen::{JsCast, prelude::*};

mod transact;

fn execute_hashes_to_js(result: Option<Vec<String>>) -> Result<JsValue, JsError> {
    match result {
        None => Ok(JsValue::NULL),
        Some(hashes) => Ok(serde_wasm_bindgen::to_value(&hashes)?),
    }
}

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
            &JsValue::from_f64(f64::from(current)),
        );
    }
    if let Some(total) = total {
        let _ = Reflect::set(
            &obj,
            &JsValue::from_str("total"),
            &JsValue::from_f64(f64::from(total)),
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
    pub fn new(rpc_url: &str, contract_config: &'static ContractConfig) -> anyhow::Result<Self> {
        Ok(Self {
            storage_bridge: StorageWorker::spawner()
                .as_module(true)
                .spawn("./js/storage-worker.js"),
            prover_bridge: ProverWorker::spawner()
                .as_module(true)
                .spawn("./js/prover-worker.js"),
            fetcher: Rc::new(CoreStateFetcher::new(rpc_url, contract_config)?),
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
}

#[wasm_bindgen]
impl WebClient {
    #[wasm_bindgen(js_name = aspState)]
    pub async fn asp_state(&self) -> Result<JsValue, JsError> {
        let asp_state = self
            .fetcher
            .asp_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_state)?)
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

    #[wasm_bindgen(js_name = keyDerivationMessage)]
    pub fn key_derivation_message(&self) -> String {
        KEY_DERIVATION_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = deriveAndSaveUserKeys)]
    pub async fn derive_save_user_keys(
        &self,
        address: String,
        signature: Vec<u8>,
    ) -> Result<(), JsError> {
        let req = StorageWorkerRequest::DeriveSaveUserKeys(
            address,
            KeyDerivationSignature(signature),
            self.fetcher.contract_config().network.clone(),
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

    #[wasm_bindgen(js_name = getASPSecret)]
    pub async fn get_asp_secret(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::AspSecret(address);

        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::AspSecret(secret) => Ok(serde_wasm_bindgen::to_value(&secret)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = deriveAspUserLeaf)]
    pub async fn derive_asp_user_leaf(
        &self,
        membership_blinding: BigInt,
        pubkey_hex: &str,
    ) -> Result<JsValue, JsError> {
        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;

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

    #[wasm_bindgen(js_name = executeDeposit)]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_deposit(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
        output_amounts: Array,
        submit_fn: Function,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let result = self
            .execute_deposit_inner(
                pool_contract_id,
                user_address,
                amount,
                output_amounts,
                submit_fn,
                on_status,
            )
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen(js_name = plan)]
    pub async fn plan(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
    ) -> Result<JsValue, JsError> {
        let preview = self
            .plan_inner(pool_contract_id, user_address, amount)
            .await?;
        Ok(serde_wasm_bindgen::to_value(&preview)?)
    }

    #[wasm_bindgen(js_name = executeTransfer)]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_transfer(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
        recipient_note_key_hex: String,
        recipient_enc_key_hex: String,
        submit_fn: Function,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        use tx_planner::SpendTarget;

        let recipient_note = NotePublicKey::parse(&recipient_note_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let recipient_enc = EncryptionPublicKey::parse(&recipient_enc_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let target = SpendTarget::transfer(recipient_note, recipient_enc);

        let result = self
            .execute_spend_inner(
                pool_contract_id,
                user_address,
                amount,
                target,
                "transfer",
                submit_fn,
                on_status,
            )
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen(js_name = executeWithdraw)]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_withdraw(
        &self,
        pool_contract_id: String,
        user_address: String,
        withdraw_recipient: String,
        amount: BigInt,
        submit_fn: Function,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        use tx_planner::SpendTarget;

        let target = SpendTarget::withdraw(withdraw_recipient);

        let result = self
            .execute_spend_inner(
                pool_contract_id,
                user_address,
                amount,
                target,
                "withdraw",
                submit_fn,
                on_status,
            )
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen(js_name = executeTransact)]
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_transact_wasm(
        &self,
        pool_contract_id: String,
        user_address: String,
        ext_recipient: String,
        ext_amount: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        submit_fn: Function,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let result = self
            .execute_transact_inner(
                pool_contract_id,
                user_address,
                ext_recipient,
                ext_amount,
                input_note_ids,
                output_amounts,
                out_recipient_note_keys_hex,
                out_recipient_enc_keys_hex,
                submit_fn,
                on_status,
                "transact",
            )
            .await?;
        execute_hashes_to_js(result)
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for WebClient {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<types::SyncMetadata>> {
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

    async fn save_sync_progress(
        &self,
        metadata: Vec<types::SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        let mut bridge = self.storage_bridge.fork();
        let resp = with_timeout(
            10_000,
            bridge.run(StorageWorkerRequest::SaveSyncProgress(
                metadata,
                fully_indexed,
            )),
        )
        .await?;
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
    Field::from_str(s).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_input_note_ids(
    input_note_ids: &Array,
    min_len: u32,
    max_len: u32,
    len_err: &'static str,
) -> Result<Vec<Field>, JsError> {
    let len = input_note_ids.length();
    if len < min_len || len > max_len {
        return Err(JsError::new(len_err));
    }

    let mut input_commitments = Vec::with_capacity(len as usize);
    for i in 0..len {
        let v = input_note_ids.get(i);
        let s = v
            .as_string()
            .ok_or_else(|| JsError::new("input_note_ids must be string[]"))?;
        input_commitments.push(parse_field_hex_str(&s)?);
    }
    Ok(input_commitments)
}

fn parse_output_amounts(output_amounts: &Array) -> Result<[NoteAmount; N_OUTPUTS], JsError> {
    let expected_outputs =
        u32::try_from(N_OUTPUTS).map_err(|_| JsError::new("N_OUTPUTS exceeds u32"))?;
    if output_amounts.length() != expected_outputs {
        return Err(JsError::new(&format!(
            "output_amounts must have length {N_OUTPUTS}"
        )));
    }

    let mut out_amounts = [NoteAmount::ZERO; N_OUTPUTS];
    for (i, out) in out_amounts.iter_mut().enumerate().take(N_OUTPUTS) {
        let idx = u32::try_from(i).map_err(|_| JsError::new("output index exceeds u32"))?;
        let v = output_amounts.get(idx);
        let bi: BigInt = v
            .dyn_into()
            .map_err(|_| JsError::new("output_amounts must be BigInt[]"))?;
        *out = parse_note_amount_decimal(&bi)?;
    }
    Ok(out_amounts)
}

type OutputRecipientKeys = (
    [Option<NotePublicKey>; N_OUTPUTS],
    [Option<EncryptionPublicKey>; N_OUTPUTS],
);

fn parse_output_recipient_keys(
    out_recipient_note_keys_hex: &Array,
    out_recipient_enc_keys_hex: &Array,
) -> Result<OutputRecipientKeys, JsError> {
    let mut out_note_pks: [Option<NotePublicKey>; N_OUTPUTS] = [None, None];
    let mut out_enc_pks: [Option<EncryptionPublicKey>; N_OUTPUTS] = [None, None];
    for i in 0..N_OUTPUTS {
        let idx = u32::try_from(i).map_err(|_| JsError::new("output index exceeds u32"))?;
        let nk = out_recipient_note_keys_hex.get(idx);
        let ek = out_recipient_enc_keys_hex.get(idx);

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
    Ok((out_note_pks, out_enc_pks))
}

fn parse_u32_decimal(s: &str) -> Result<u32, String> {
    let v: u64 = s
        .parse::<u64>()
        .map_err(|_| format!("invalid decimal u64: {s}"))?;
    u32::try_from(v).map_err(|_| format!("value does not fit into u32: {s}"))
}
