use crate::{
    deployment::deployment_config,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    storage::Storage,
    workers::prover::{ProverBridge, ProverWorker},
};
use gloo_worker::Spawnable;
use std::rc::Rc;
use stellar_private_payments_sdk::{
    Account as NativeAccount, Client, Handle, SyncMode,
    types::{DisclosureReceipt, DisclosureVerificationReport, KeyDerivationSignature},
    verify_disclosure_receipt,
};
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

use super::pool_err;

const DEFAULT_PROVER_WORKER_URL: &str = "./workers/prover-worker.js";

/// Worker wiring and SDK client bootstrap shared by [`super::Client`] and
/// [`super::Account`].
pub(crate) struct ClientCore {
    storage: StorageBridge,
    prover_bridge: ProverBridge,
    native_client: Rc<Client<StorageBridge>>,
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

        let prover_worker_url =
            prover_worker_url.unwrap_or_else(|| DEFAULT_PROVER_WORKER_URL.to_string());

        let prover_bridge = ProverBridge::new(
            ProverWorker::spawner()
                .with_loader(true)
                .as_module(true)
                .spawn(&prover_worker_url),
        );
        let prover: Handle<dyn stellar_private_payments_sdk::Prover> = Handle::from_box(Box::new(
            prover_bridge.clone(),
        )
            as Box<dyn stellar_private_payments_sdk::Prover>);
        let native_client = Rc::new(Client::new(
            storage_bridge.clone(),
            prover,
            SyncMode::Background,
            (*contract_config).clone(),
            rpc_url,
        ));
        let core = Self {
            storage: storage_bridge,
            prover_bridge,
            native_client,
        };

        core.ping_storage()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(core)
    }

    pub(crate) fn native_client(&self) -> Rc<Client<StorageBridge>> {
        self.native_client.clone()
    }

    pub(crate) fn storage_bridge(&self) -> StorageBridge {
        self.storage.clone()
    }

    pub(crate) fn key_derivation_message(&self) -> String {
        stellar_private_payments_sdk::tx::encryption::KEY_DERIVATION_MESSAGE.to_string()
    }

    pub(crate) async fn sync(&self) -> Result<(), JsError> {
        self.native_client.sync().await.map_err(pool_err)
    }

    pub(crate) async fn ensure_prover(&self) -> Result<(), JsError> {
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))
    }

    pub(crate) async fn account(
        &self,
        wallet_signer: crate::signer::WalletSigner,
        user_address: String,
    ) -> Result<NativeAccount<StorageBridge>, JsError> {
        self.ensure_prover().await?;
        let signer: Handle<dyn stellar_private_payments_sdk::Signer> = Handle::from_box(Box::new(
            wallet_signer,
        )
            as Box<dyn stellar_private_payments_sdk::Signer>);
        self.native_client
            .account(user_address, signer)
            .map_err(pool_err)
    }

    pub(crate) async fn user_keys_exist(&self, address: &str) -> Result<bool, JsError> {
        let req = StorageWorkerRequest::UserKeys(address.to_string());
        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(Some(_)) => Ok(true),
            StorageWorkerResponse::UserKeys(None) => Ok(false),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    pub(crate) async fn derive_save_user_keys(
        &self,
        address: String,
        signature: Vec<u8>,
    ) -> Result<(), JsError> {
        let config = deployment_config()?;
        let req = StorageWorkerRequest::DeriveSaveUserKeys(
            address,
            KeyDerivationSignature(signature),
            config.network.clone(),
        );

        match self.storage_request(req, 5_000).await? {
            StorageWorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    /// Walletless selective-disclosure verification (Groth16 + context +
    /// roots).
    pub(crate) async fn verify_selective_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<DisclosureVerificationReport, stellar_private_payments_sdk::Error> {
        self.ping_prover().await.map_err(|e| {
            stellar_private_payments_sdk::Error::Other(format!("failed to load prover: {e:?}"))
        })?;
        let fetcher = self.native_client.state_fetcher().map_err(|e| {
            stellar_private_payments_sdk::Error::Other(format!("state fetcher: {e:#}"))
        })?;
        verify_disclosure_receipt(&fetcher, &self.prover_bridge, receipt, expected_vk_hash).await
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
