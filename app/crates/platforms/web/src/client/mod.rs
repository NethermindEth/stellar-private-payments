use crate::{
    protocol::{
        AdminASPRequest, DisclosureInputsRequest, DisclosureProverRequest, ProverWorkerRequest,
        ProverWorkerResponse, StorageWorkerRequest, StorageWorkerResponse,
    },
    workers::{
        prover::{ProverBridge, ProverWorker},
        storage::{StorageBridge, StorageWorker},
    },
};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::Spawnable;
use js_sys::{Array, BigInt, Function, Object, Reflect};
use serde_json::Value as JsonValue;
use std::{collections::HashSet, rc::Rc, str::FromStr};
use stellar_private_payments_sdk::{
    PoolError,
    chain::{StateFetcher, TransactionEnvelope, TxConfirmStatus, confirm_tx, submit_tx},
    state::{APP_SETTING_BOOTNODE_CONFIG, APP_SETTING_EXPLORER},
    tx::{encryption::KEY_DERIVATION_MESSAGE, flows::N_OUTPUTS},
    types::{
        AspMembershipSync, BootnodeSetting, ContractConfig, DisclosureReceipt, EncryptionPublicKey,
        ExtAmount, Field, KeyDerivationSignature, NoteAmount, NotePublicKey, parse_0x_hex_32,
    },
};
use wasm_bindgen::{JsCast, prelude::*};

mod disclosure;
mod pool;
mod transact;

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

pub(crate) fn pool_err_message(error: PoolError) -> String {
    match &error {
        PoolError::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            "register at ASP before transacting".into()
        }
        PoolError::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            "indexer sync in progress; try again shortly".into()
        }
        _ => error.to_string(),
    }
}

pub(crate) fn pool_err(error: PoolError) -> JsError {
    JsError::new(&pool_err_message(error))
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
#[derive(Clone)]
pub struct WebClient {
    rpc_url: String,
    storage: StorageBridge,
    prover_bridge: ProverBridge,
    fetcher: Rc<StateFetcher>,
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

    #[wasm_bindgen(js_name = getSetting)]
    pub async fn get_setting(&self, key: String) -> Result<JsValue, JsError> {
        match self
            .storage_request(StorageWorkerRequest::GetSetting(key), 2_000)
            .await?
        {
            StorageWorkerResponse::Setting(value_json) => {
                let parsed = value_json
                    .map(|raw| serde_json::from_str::<JsonValue>(&raw))
                    .transpose()
                    .map_err(|e| JsError::new(&e.to_string()))?;
                let serializer =
                    serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
                Ok(serde::Serialize::serialize(&parsed, &serializer)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = setSetting)]
    pub async fn set_setting(&self, key: String, value: JsValue) -> Result<(), JsError> {
        let value_json = serde_wasm_bindgen::from_value::<JsonValue>(value)
            .map_err(|e| JsError::new(&e.to_string()))?;
        match self
            .storage_request(
                StorageWorkerRequest::SetSetting {
                    key,
                    value_json: serde_json::to_string(&value_json)
                        .map_err(|e| JsError::new(&e.to_string()))?,
                },
                2_000,
            )
            .await?
        {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = setBootnodeConfig)]
    pub async fn set_bootnode_config(&self, url: String) -> Result<(), JsError> {
        self.set_setting(
            APP_SETTING_BOOTNODE_CONFIG.to_string(),
            serde_wasm_bindgen::to_value(&BootnodeSetting { enabled: true, url })?,
        )
        .await
    }

    #[wasm_bindgen(js_name = getBootnodeConfig)]
    pub async fn get_bootnode_config(&self) -> Result<JsValue, JsError> {
        self.get_setting(APP_SETTING_BOOTNODE_CONFIG.to_string())
            .await
    }

    #[wasm_bindgen(js_name = getExplorerSetting)]
    pub async fn get_explorer_setting(&self) -> Result<JsValue, JsError> {
        self.get_setting(APP_SETTING_EXPLORER.to_string()).await
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
    pub async fn get_user_notes(
        &self,
        address: String,
        offset: u32,
        limit: u32,
    ) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::UserNotes { address, offset, limit };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::UserNotes(list) => Ok(serde_wasm_bindgen::to_value(&list)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserNotesCount)]
    pub async fn get_user_notes_count(&self, address: String) -> Result<u32, JsError> {
        let req = StorageWorkerRequest::CountUserNotes(address);
        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserNotesCount(count) => Ok(count),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getPortfolioBalances)]
    pub async fn get_portfolio_balances(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::PortfolioBalances(address);
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::PortfolioBalances(list) => {
                Ok(serde_wasm_bindgen::to_value(&list)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = recordOperation)]
    #[allow(clippy::too_many_arguments)]
    pub async fn record_operation(
        &self,
        address: String,
        pool_contract_id: String,
        op_type: String,
        amount: String,
        direction: String,
        counterparty: Option<String>,
        tx_hash: Option<String>,
    ) -> Result<(), JsError> {
        let req = StorageWorkerRequest::RecordOperation {
            address,
            pool_contract_id,
            op_type,
            amount,
            direction,
            counterparty,
            tx_hash,
        };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = listOperations)]
    pub async fn list_operations(
        &self,
        address: String,
        pool_contract_id: String,
        limit: u32,
    ) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::ListOperations {
            address,
            pool_contract_id,
            limit,
        };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::Operations(list) => Ok(serde_wasm_bindgen::to_value(&list)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = lookupRegisteredPublicKey)]
    pub async fn lookup_registered_public_key(&self, address: String) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::RecipientLookup {
            address,
            public_key_registry_contract_id: self
                .fetcher
                .contract_config()
                .public_key_registry
                .clone(),
        };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::RecipientLookup(lookup) => {
                Ok(serde_wasm_bindgen::to_value(&lookup)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getOperationalFeed)]
    pub async fn get_operational_feed(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::OperationalFeed {
            limit,
            asp_membership_contract_id: self.fetcher.contract_config().asp_membership.clone(),
            public_key_registry_contract_id: self
                .fetcher
                .contract_config()
                .public_key_registry
                .clone(),
        };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::OperationalFeed(list) => {
                Ok(serde_wasm_bindgen::to_value(&list)?)
            }
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = generateSelectiveDisclosure)]
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_selective_disclosure(
        &self,
        pool_contract_id: String,
        user_address: String,
        selected_commitment_hexes: Array,
        authority_label: String,
        authority_identity_payload_hex: String,
        purpose: String,
        context_nonce: BigInt,
        on_status: Option<Function>,
    ) -> Result<JsValue, JsError> {
        let selected_commitments = parse_disclosure_commitments(&selected_commitment_hexes)?;
        let receipt = self
            .generate_selective_disclosure_inner(
                &pool_contract_id,
                &user_address,
                selected_commitments,
                authority_label,
                authority_identity_payload_hex,
                purpose,
                context_nonce,
                on_status,
            )
            .await?;
        match receipt {
            None => Ok(JsValue::NULL),
            Some(r) => Ok(serde_wasm_bindgen::to_value(&r)?),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn generate_selective_disclosure_inner(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        selected_commitments: Vec<Field>,
        authority_label: String,
        authority_identity_payload_hex: String,
        purpose: String,
        context_nonce: BigInt,
        on_status: Option<Function>,
    ) -> Result<Option<DisclosureReceipt>, JsError> {
        if selected_commitments.is_empty() || selected_commitments.len() > 4 {
            return Err(JsError::new(
                "selective disclosure requires 1..=4 selected commitments",
            ));
        }
        let context_nonce = parse_field_bigint_numeric(&context_nonce)?;

        emit_progress(
            &on_status,
            "disclosure",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        let (inputs, network, pool_address) = loop {
            emit_progress(
                &on_status,
                "disclosure",
                "fetch_chain_state",
                "Fetching on-chain state…",
                None,
                None,
            );
            let data = self
                .fetcher
                .contracts_data_for_pool(pool_contract_id)
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool = data.pools.into_iter().next().ok_or_else(|| {
                JsError::new(&format!(
                    "pool {pool_contract_id} not found in contract state"
                ))
            })?;
            let pool_root = pool.merkle_root;
            let pool_next_index =
                parse_u32_decimal(&pool.merkle_next_index).map_err(|e| JsError::new(&e))?;

            let req = DisclosureInputsRequest {
                user_address: user_address.to_string(),
                pool_address: pool_contract_id.to_string(),
                selected_commitments: selected_commitments.clone(),
                pool_root,
                pool_next_index,
                tree_depth: pool.merkle_levels,
            };

            emit_progress(
                &on_status,
                "disclosure",
                "load_state",
                "Building witness inputs…",
                None,
                None,
            );
            match self
                .storage_request(StorageWorkerRequest::DisclosureInputs(req), 5_000)
                .await?
            {
                StorageWorkerResponse::DisclosureInputs(inputs) => {
                    break (
                        inputs,
                        self.fetcher.contract_config().network.clone(),
                        pool.contract_id,
                    );
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!(
                        "[DISCLOSURE] the account {user_address} should register within ASP"
                    );
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[DISCLOSURE] sync is needed - waiting the indexer");
                    emit_progress(
                        &on_status,
                        "disclosure",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting to sync {gap} ledger(s) from the chain...")
                        } else {
                            "Waiting to sync ledgers from the chain...".to_string()
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

        emit_progress(&on_status, "disclosure", "prove", "Proving…", None, None);
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prover_req = DisclosureProverRequest {
            inputs: inputs.notes,
            network,
            pool_address,
            authority_label,
            authority_identity_payload_hex,
            purpose,
            context_nonce,
        };

        let receipt = match self
            .prover_request(ProverWorkerRequest::Disclosure(prover_req), 20_000)
            .await?
        {
            ProverWorkerResponse::Disclosure(receipt) => receipt,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(receipt))
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

fn parse_disclosure_commitments(arr: &Array) -> Result<Vec<Field>, JsError> {
    let len = arr.length();
    if len == 0 || len > 4 {
        return Err(JsError::new(
            "selected_commitment_hexes must contain 1..=4 commitment strings",
        ));
    }
    let mut commitments = Vec::with_capacity(len as usize);
    let mut seen = HashSet::with_capacity(len as usize);
    for i in 0..len {
        let v = arr.get(i);
        let s = v
            .as_string()
            .ok_or_else(|| JsError::new("selected_commitment_hexes must be string[]"))?;
        let commitment = parse_field_hex_str(&s)?;
        if !seen.insert(commitment) {
            return Err(JsError::new(&format!(
                "duplicate commitment in selected_commitment_hexes at index {i}"
            )));
        }
        commitments.push(commitment);
    }
    Ok(commitments)
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
