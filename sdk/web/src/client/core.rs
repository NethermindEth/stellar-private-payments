use crate::{
    deployment::deployment_config,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    storage::Storage,
    workers::prover::{ProverBridge, ProverWorker},
};
use gloo_timers::future::TimeoutFuture;
use gloo_worker::Spawnable;
use std::rc::Rc;
use stellar_private_payments_sdk::{
    chain::{StateFetcher, TransactionEnvelope, TxConfirmStatus, confirm_tx, submit_tx},
    tx::encryption::KEY_DERIVATION_MESSAGE,
    types::{ContractConfig, KeyDerivationSignature, parse_0x_hex_32},
};
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

use super::{PoolCreateConfig, build_pool_config, pool_err};

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

const DEFAULT_PROVER_WORKER_URL: &str = "./workers/prover-worker.js";

/// Workers, RPC fetcher, and tx submission shared by [`super::Client`] and
/// [`super::PrivatePool`].
pub(crate) struct ClientCore {
    rpc_url: String,
    storage: StorageBridge,
    prover_bridge: ProverBridge,
    fetcher: Rc<StateFetcher>,
}

impl Clone for ClientCore {
    fn clone(&self) -> Self {
        Self {
            rpc_url: self.rpc_url.clone(),
            storage: self.storage.clone(),
            prover_bridge: self.prover_bridge.clone(),
            fetcher: self.fetcher.clone(),
        }
    }
}

impl ClientCore {
    pub(crate) async fn connect(
        rpc_url: String,
        storage: Option<Storage>,
        storage_worker_url: Option<String>,
        prover_worker_url: Option<String>,
    ) -> Result<Self, JsError> {
        crate::wasm_start();

        let contract_config = deployment_config()?;
        let storage_bridge = match storage {
            Some(storage) => storage.bridge(),
            None => {
                let worker_url = storage_worker_url
                    .unwrap_or_else(|| crate::storage::DEFAULT_STORAGE_WORKER_URL.to_string());
                Storage::open_internal(worker_url).await?.bridge()
            }
        };

        let core = Self::new_with_storage(
            rpc_url,
            storage_bridge,
            prover_worker_url.unwrap_or_else(|| DEFAULT_PROVER_WORKER_URL.to_string()),
            contract_config,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;

        core.ping_storage()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(core)
    }

    pub(crate) fn storage(&self) -> StorageBridge {
        self.storage.clone()
    }

    pub(crate) fn contract_config(&self) -> &ContractConfig {
        self.fetcher.contract_config()
    }

    pub(crate) fn key_derivation_message(&self) -> String {
        KEY_DERIVATION_MESSAGE.to_string()
    }

    pub(crate) async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self
            .fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    pub(crate) async fn lookup_registered_public_key(
        &self,
        address: String,
    ) -> Result<JsValue, JsError> {
        let req = StorageWorkerRequest::RecipientLookup {
            address,
            public_key_registry_contract_id: self.contract_config().public_key_registry.clone(),
        };
        match self.storage_request(req, 2_000).await? {
            StorageWorkerResponse::RecipientLookup(lookup) => {
                Ok(serde_wasm_bindgen::to_value(&lookup)?)
            }
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    pub(crate) async fn derive_save_user_keys(
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
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    pub(crate) async fn user_public_keys_hex(
        &self,
        address: &str,
    ) -> Result<(String, String), JsError> {
        let req = StorageWorkerRequest::UserKeys(address.to_string());
        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(Some(keys)) => {
                use stellar_private_payments_sdk::types::encode_0x_hex;
                Ok((
                    encode_0x_hex(&keys.note_keypair.public.0),
                    encode_0x_hex(&keys.encryption_keypair.public.0),
                ))
            }
            StorageWorkerResponse::UserKeys(None) => Err(JsError::new(
                "user keys not found in local storage; call initialize() first",
            )),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    pub(crate) async fn create_pool_internal(
        &self,
        cfg: &PoolCreateConfig,
        wallet_signer: &crate::signer::WalletSigner,
    ) -> Result<stellar_private_payments_sdk::PrivatePool<StorageBridge>, JsError> {
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let contract_config = self.fetcher.contract_config().clone();
        let pool_config = build_pool_config(
            self.rpc_url.clone(),
            contract_config,
            cfg.pool_contract.clone(),
            cfg.user_address.clone(),
        );
        let signer: Box<dyn stellar_private_payments_sdk::Signer> = Box::new(wallet_signer.clone());
        let prover: Box<dyn stellar_private_payments_sdk::Prover> =
            Box::new(self.prover_bridge.clone());

        stellar_private_payments_sdk::PrivatePool::init(pool_config, self.storage(), signer, prover)
            .map_err(pool_err)
    }

    pub(crate) async fn register_public_keys(
        &self,
        wallet_signer: &crate::signer::WalletSigner,
        user_address: String,
        note_public_key_hex: String,
        encryption_public_key_hex: String,
    ) -> Result<String, JsError> {
        let note_key = parse_hex32(&note_public_key_hex, "note public key")?;
        let encryption_key = parse_hex32(&encryption_public_key_hex, "encryption public key")?;
        let prepared = self
            .fetcher
            .prepare_register(&user_address, note_key, encryption_key)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        let signed_tx = wallet_signer.sign_prepared_transaction(&prepared).await?;
        self.submit_and_confirm(&signed_tx).await
    }

    pub(crate) async fn recipient_keys(&self, address: &str) -> Result<(String, String), JsError> {
        use stellar_private_payments_sdk::types::RecipientLookup;

        let lookup: RecipientLookup = {
            let req = StorageWorkerRequest::RecipientLookup {
                address: address.to_string(),
                public_key_registry_contract_id: self.contract_config().public_key_registry.clone(),
            };
            match self.storage_request(req, 2_000).await? {
                StorageWorkerResponse::RecipientLookup(lookup) => lookup,
                other => {
                    return Err(JsError::new(&format!("unexpected response: {other:?}")));
                }
            }
        };

        let entry = lookup
            .entry
            .ok_or_else(|| JsError::new(&format!("no public keys registered for {address}")))?;

        use stellar_private_payments_sdk::types::encode_0x_hex;

        Ok((
            encode_0x_hex(&entry.note_key.0),
            encode_0x_hex(&entry.encryption_key.0),
        ))
    }

    pub(super) async fn confirm_tx(&self, hash: &str) -> Result<(), JsError> {
        let rpc = self.fetcher.rpc();

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                TimeoutFuture::new(CONFIRM_POLL_INTERVAL_MS).await;
            }
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

    pub(super) async fn submit_and_confirm(
        &self,
        signed: &TransactionEnvelope,
    ) -> Result<String, JsError> {
        let rpc = self.fetcher.rpc();
        let hash = submit_tx(signed, rpc)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.confirm_tx(&hash).await?;
        Ok(hash)
    }

    fn new_with_storage(
        rpc_url: String,
        storage: StorageBridge,
        prover_worker_url: String,
        contract_config: &'static ContractConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            rpc_url: rpc_url.clone(),
            storage,
            prover_bridge: ProverBridge::new(
                ProverWorker::spawner()
                    .as_module(true)
                    .spawn(&prover_worker_url),
            ),
            fetcher: Rc::new(StateFetcher::new(&rpc_url, (*contract_config).clone())?),
        })
    }

    async fn storage_request(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsError> {
        self.storage
            .call(req, timeout_ms)
            .await
            .map_err(|e| JsError::new(&format!("storage worker error: {e}")))
    }

    async fn ping_storage(&self) -> anyhow::Result<()> {
        self.storage.ping().await
    }

    async fn ping_prover(&self) -> anyhow::Result<()> {
        self.prover_bridge.ping().await
    }
}

fn parse_hex32(hex: &str, what: &str) -> Result<[u8; 32], JsError> {
    parse_0x_hex_32(hex.trim()).map_err(|e| JsError::new(&format!("Invalid {what}: {e}")))
}
