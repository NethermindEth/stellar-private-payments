//! Wasm [`Client`] — thin browser wrapper around the native SDK
//! [`Client`](NativeClient).

mod account;
mod execute;
mod pool;
mod transact;

use std::rc::Rc;

use serde::Deserialize;
use stellar_private_payments_sdk::{
    Account as NativeAccount, Client as NativeClient, Error, Handle,
    chain::StateFetcher,
    types::{DisclosureReceipt, KeyDerivationSignature},
    verify_disclosure_receipt,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    deployment::deployment_config,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    signer::WalletSigner,
    storage::Storage,
    workers::{
        prover::{ProverBridge, ProverWorker},
        storage::StorageBridge,
    },
};
use gloo_worker::Spawnable;

pub use account::Account;
pub use pool::PrivatePool;

pub(crate) fn pool_err(error: Error) -> JsError {
    use stellar_private_payments_sdk::types::AspMembershipSync;

    match &error {
        Error::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        Error::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        _ => JsError::new(&error.to_string()),
    }
}

pub(crate) fn pool_err_message(error: Error) -> String {
    error.to_string()
}

/// Deployment-scoped browser SDK runtime: native [`NativeClient`] plus worker
/// handles.
#[wasm_bindgen]
pub struct Client {
    storage: Storage,
    inner: NativeClient<StorageBridge>,
    prover: ProverBridge,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountOptions {
    network_passphrase: String,
    user_address: Option<String>,
}

#[wasm_bindgen]
impl Client {
    /// Build the native client and spawn the prover worker.
    ///
    /// `prover_worker_url` must be an absolute URL (the JS package entry
    /// resolves it via `import.meta.url`). Call [`crate::bootnode_required_js`]
    /// if needed, then [`Client::background_sync`], then [`Client::account`]
    /// before pool operations.
    #[wasm_bindgen(js_name = new)]
    pub async fn new(
        rpc_url: String,
        storage: &Storage,
        prover_worker_url: String,
        bootnode_url: Option<String>,
    ) -> Result<Client, JsError> {
        crate::wasm_start();

        if prover_worker_url.trim().is_empty() {
            return Err(JsError::new(
                "proverWorkerUrl is required (absolute URL to prover-worker.js)",
            ));
        }

        let storage = storage.fork();
        let storage_bridge = storage.bridge();
        storage_bridge
            .ping()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        let contract_config = deployment_config()?;
        let prover = ProverBridge::new(
            ProverWorker::spawner()
                .with_loader(true)
                .as_module(true)
                .spawn(&prover_worker_url),
        );
        let prover_handle: Handle<dyn stellar_private_payments_sdk::Prover> = Handle::from_box(
            Box::new(prover.clone()) as Box<dyn stellar_private_payments_sdk::Prover>,
        );

        let inner = NativeClient::init(
            rpc_url,
            storage_bridge,
            prover_handle,
            (*contract_config).clone(),
            bootnode_url.clone(),
        )
        .map_err(pool_err)?;

        Ok(Self {
            storage,
            inner,
            prover,
        })
    }

    /// Bundled deployment config (contract addresses, pools, network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config() -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
    }

    /// Start background contract-event sync into local storage.
    ///
    /// Does not probe retention — call [`crate::bootnode_required_js`] first
    /// and pass any required bootnode to [`Client::new`]. Callers should
    /// avoid spawning more than once per page.
    #[wasm_bindgen(js_name = backgroundSync)]
    pub async fn background_sync(&mut self) -> Result<(), JsError> {
        let sync = self.inner.background_sync().map_err(pool_err)?;
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = sync.run().await {
                log::error!("background sync stopped: {e}");
            }
        });
        Ok(())
    }

    /// Bind a wallet signer, derive privacy keys when missing, and return an
    /// [`Account`] session.
    pub async fn account(&self, options: JsValue, signer: JsValue) -> Result<Account, JsError> {
        let opts: AccountOptions = serde_wasm_bindgen::from_value(options)?;
        let user_address = resolve_user_address(&signer, opts.user_address).await?;
        let wallet_signer =
            WalletSigner::new(signer, opts.network_passphrase, user_address.clone())?;

        self.ensure_prover().await?;

        if !self.user_keys_exist(&user_address).await? {
            let message = stellar_private_payments_sdk::KEY_DERIVATION_MESSAGE.to_string();
            let sig_hex = wallet_signer.sign_wallet_message(&message).await?;
            let signature = crate::signer::wallet_message_signature_to_bytes(&sig_hex)?;
            self.derive_save_user_keys(user_address.clone(), signature)
                .await?;
        }

        Ok(Account::new(Rc::new(
            self.open_native_account(wallet_signer, user_address)?,
        )))
    }

    /// Catch local storage up to the current chain tip for the deployment.
    #[wasm_bindgen(js_name = sync)]
    pub async fn sync(&self) -> Result<(), JsError> {
        self.inner.sync().await.map_err(pool_err)
    }

    /// Recent deployment activity (pool events, registry registrations, ASP
    /// updates).
    #[wasm_bindgen(js_name = operationalFeed)]
    pub async fn operational_feed(&self, limit: u32) -> Result<JsValue, JsError> {
        let feed = self.inner.operational_feed(limit).await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&feed)?)
    }

    /// Look up a recipient's registered note and encryption public keys.
    #[wasm_bindgen(js_name = recipientLookup)]
    pub async fn recipient_lookup(&self, address: String) -> Result<JsValue, JsError> {
        let lookup = self
            .inner
            .recipient_lookup(&address)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&lookup)?)
    }

    /// On-chain ASP membership and non-membership state.
    #[wasm_bindgen(js_name = aspState)]
    pub async fn asp_state(&self) -> Result<JsValue, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .asp_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let fetcher = self.state_fetcher()?;
        let data = fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// Verify a selective-disclosure receipt without a wallet session.
    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &self,
        receipt_json: String,
        expected_vk_hash: String,
    ) -> Result<JsValue, JsError> {
        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;

        self.ensure_prover().await?;
        let fetcher = self.state_fetcher()?;
        let report = verify_disclosure_receipt(&fetcher, &self.prover, &receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }
}

impl Client {
    fn state_fetcher(&self) -> Result<StateFetcher, JsError> {
        self.inner
            .state_fetcher()
            .map_err(|e| JsError::new(&e.to_string()))
    }

    async fn ensure_prover(&self) -> Result<(), JsError> {
        self.prover
            .ping()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))
    }

    fn open_native_account(
        &self,
        wallet_signer: WalletSigner,
        user_address: String,
    ) -> Result<NativeAccount<StorageBridge>, JsError> {
        let signer: Handle<dyn stellar_private_payments_sdk::Signer> = Handle::from_box(Box::new(
            wallet_signer,
        )
            as Box<dyn stellar_private_payments_sdk::Signer>);
        self.inner.account(user_address, signer).map_err(pool_err)
    }

    async fn user_keys_exist(&self, address: &str) -> Result<bool, JsError> {
        let req = StorageWorkerRequest::UserKeys(address.to_string());
        match self.storage_request(req, 1_000).await? {
            StorageWorkerResponse::UserKeys(Some(_)) => Ok(true),
            StorageWorkerResponse::UserKeys(None) => Ok(false),
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    async fn derive_save_user_keys(
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

    async fn storage_request(
        &self,
        req: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsError> {
        self.storage
            .bridge()
            .call(req, timeout_ms)
            .await
            .map_err(|e| JsError::new(&format!("storage worker error: {e}")))
    }
}

async fn resolve_user_address(
    signer: &JsValue,
    options_address: Option<String>,
) -> Result<String, JsError> {
    if let Some(addr) = options_address {
        return Ok(addr);
    }

    let get_pk = js_sys::Reflect::get(signer, &JsValue::from_str("getPublicKey"))
        .map_err(|_| JsError::new("userAddress required or signer.getPublicKey"))?;
    if !get_pk.is_function() {
        return Err(JsError::new(
            "userAddress required or signer must implement getPublicKey",
        ));
    }

    let func = get_pk.dyn_ref::<js_sys::Function>().ok_or_else(|| {
        JsError::new("userAddress required or signer must implement getPublicKey")
    })?;

    let value = func
        .call0(signer)
        .map_err(|_| JsError::new("getPublicKey failed"))?;

    let resolved = if value.is_instance_of::<js_sys::Promise>() {
        JsFuture::from(
            value
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| JsError::new("getPublicKey failed"))?,
        )
        .await
        .map_err(|_| JsError::new("getPublicKey failed"))?
    } else {
        value
    };

    resolved
        .as_string()
        .ok_or_else(|| JsError::new("getPublicKey did not return a string"))
}
