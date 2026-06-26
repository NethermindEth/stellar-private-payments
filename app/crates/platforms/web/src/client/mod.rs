use crate::{
    protocol::{
        AdminASPRequest, ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest,
        StorageWorkerResponse,
    },
    workers::{
        prover::{ProverBridge, ProverWorker},
        storage::{StorageBridge, StorageWorker},
    },
};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::Spawnable;
use js_sys::{Array, BigInt, Function, Object, Reflect};
use std::{rc::Rc, str::FromStr};
use stellar_private_payments_sdk::{
    PoolError,
    chain::{StateFetcher, TransactionEnvelope, TxConfirmStatus, confirm_tx, submit_tx},
    tx::{encryption::KEY_DERIVATION_MESSAGE, flows::N_OUTPUTS},
    types::{
        AspMembershipSync, ContractConfig, DisclosureReceipt, EncryptionPublicKey, ExtAmount,
        Field, KeyDerivationSignature, NoteAmount, NotePublicKey, parse_0x_hex_32,
    },
};
use wasm_bindgen::{JsCast, prelude::*};

mod disclosure;
mod pool;
mod transact;

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

pub(crate) fn pool_err(error: PoolError) -> JsError {
    match &error {
        PoolError::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        PoolError::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        _ => JsError::new(&error.to_string()),
    }
}

pub(crate) fn emit_progress(
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
    rpc_url: String,
    storage: StorageBridge,
    prover_bridge: ProverBridge,
    fetcher: Rc<StateFetcher>,
}

impl Clone for WebClient {
    fn clone(&self) -> Self {
        Self {
            rpc_url: self.rpc_url.clone(),
            storage: self.storage.clone(),
            prover_bridge: self.prover_bridge.clone(),
            fetcher: self.fetcher.clone(),
        }
    }
}

impl WebClient {
    pub fn new(rpc_url: &str, contract_config: &'static ContractConfig) -> anyhow::Result<Self> {
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            storage: StorageBridge::new(
                StorageWorker::spawner()
                    .as_module(true)
                    .spawn("./js/storage-worker.js"),
            ),
            prover_bridge: ProverBridge::new(
                ProverWorker::spawner()
                    .as_module(true)
                    .spawn("./js/prover-worker.js"),
            ),
            fetcher: Rc::new(StateFetcher::new(rpc_url, (*contract_config).clone())?),
        })
    }

    pub(super) async fn confirm_with_progress(
        &self,
        hash: &str,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<(), JsError> {
        let rpc = self.fetcher.rpc();

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            emit_progress(
                on_status,
                flow,
                "confirm",
                "Confirming…",
                Some(attempt),
                Some(CONFIRM_POLL_ATTEMPTS),
            );
            TimeoutFuture::new(CONFIRM_POLL_INTERVAL_MS).await;
            match confirm_tx(hash, rpc)
                .await
                .map_err(|e| JsError::new(&e.to_string()))?
            {
                TxConfirmStatus::Success => return Ok(()),
                TxConfirmStatus::Failed { detail } => {
                    return Err(JsError::new(&format!("transaction failed{detail}")));
                }
                TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                    return Err(JsError::new(&format!(
                        "transaction confirmation timed out after 30s (hash: {hash})"
                    )));
                }
                TxConfirmStatus::Pending => {}
            }
        }

        Err(JsError::new(&format!(
            "transaction confirmation failed (hash: {hash})"
        )))
    }

    pub(crate) fn storage(&self) -> StorageBridge {
        self.storage.clone()
    }

    pub(crate) fn prover_bridge(&self) -> ProverBridge {
        self.prover_bridge.clone()
    }

    pub(super) async fn submit_tx(
        &self,
        signed: &TransactionEnvelope,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<String, JsError> {
        let rpc = self.fetcher.rpc();
        let hash = submit_tx(signed, rpc)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.confirm_with_progress(&hash, flow, on_status).await?;
        Ok(hash)
    }

    pub async fn ping_storage(&self) -> anyhow::Result<()> {
        self.storage.ping().await
    }

    pub async fn ping_prover(&self) -> anyhow::Result<()> {
        self.prover_bridge.ping().await
    }

    async fn storage_request(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsError> {
        self.storage
            .call(req, timeout_ms)
            .await
            .map_err(|e| JsError::new(&format!("Storage Worker Communication Error: {e}")))
    }

    async fn prover_request(
        &self,
        req: ProverWorkerRequest,
        timeout_ms: u32,
    ) -> Result<ProverWorkerResponse, JsError> {
        self.prover_bridge
            .call(req, timeout_ms)
            .await
            .map_err(|e| JsError::new(&format!("Prover Worker Communication Error: {e}")))
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

    #[wasm_bindgen(js_name = registerPublicKeys)]
    pub async fn register_public_keys(
        &self,
        user_address: String,
        note_public_key_hex: String,
        encryption_public_key_hex: String,
        network_passphrase: String,
        on_status: Option<Function>,
    ) -> Result<String, JsError> {
        let note_key = parse_hex32(&note_public_key_hex, "note public key")?;
        let encryption_key = parse_hex32(&encryption_public_key_hex, "encryption public key")?;
        let prepared = self
            .fetcher
            .prepare_register(&user_address, note_key, encryption_key)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        let signed_tx =
            crate::signer::sign_prepared_transaction(&prepared, &network_passphrase, &user_address)
                .await?;
        emit_progress(&on_status, "register", "submit", "Submitting…", None, None);
        self.submit_tx(&signed_tx, "register", &on_status).await
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

    #[wasm_bindgen(js_name = setBootnodeConfig)]
    pub async fn set_bootnode_config(&self, url: String) -> Result<(), JsError> {
        let req = StorageWorkerRequest::SetBootnodeConfig { enabled: true, url };
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

    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &self,
        receipt_json: String,
        expected_vk_hash: String,
    ) -> Result<JsValue, JsError> {
        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let report = stellar_private_payments_sdk::verify_disclosure_receipt(
            &self.fetcher,
            &self.prover_bridge(),
            &receipt,
            &expected_vk_hash,
        )
        .await
        .map_err(pool_err)?;

        Ok(serde_wasm_bindgen::to_value(&report)?)
    }
}

pub(crate) fn parse_field_bigint_numeric(b: &BigInt) -> Result<Field, JsError> {
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

pub(crate) fn parse_ext_amount_decimal(b: &BigInt) -> Result<ExtAmount, JsError> {
    let s = bigint_to_string_radix(b, 10)?;
    ExtAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

pub(crate) fn parse_note_amount_decimal(b: &BigInt) -> Result<NoteAmount, JsError> {
    let s = bigint_to_string_radix(b, 10)?;
    NoteAmount::from_str(&s).map_err(|e| JsError::new(&e.to_string()))
}

pub(crate) fn parse_field_hex_str(s: &str) -> Result<Field, JsError> {
    Field::from_str(s).map_err(|e| JsError::new(&e.to_string()))
}

pub(crate) fn parse_input_note_ids(
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

pub(crate) fn parse_output_amounts(
    output_amounts: &Array,
) -> Result<[NoteAmount; N_OUTPUTS], JsError> {
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

pub(crate) fn parse_output_recipient_keys(
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

fn parse_hex32(hex: &str, what: &str) -> Result<[u8; 32], JsError> {
    parse_0x_hex_32(hex.trim()).map_err(|e| JsError::new(&format!("Invalid {what}: {e}")))
}
