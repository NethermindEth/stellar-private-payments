//! Wasm [`Client`] — deployment runtime; bind wallets via [`Account`].

mod account;
mod core;
mod execute;
mod pool;
mod transact;

use std::rc::Rc;

use serde::Deserialize;
use stellar_private_payments_sdk::{Error, chain::StateFetcher, types::DisclosureReceipt};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    deployment::deployment_config,
    events,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    signer::WalletSigner,
    storage::Storage,
};

use core::ClientCore;

pub use account::Account;
pub(crate) use pool::PoolCreateConfig;
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

/// Deployment-scoped browser SDK runtime (storage, RPC, workers).
#[wasm_bindgen]
pub struct Client {
    rpc_url: String,
    storage: Storage,
    core: Option<Rc<ClientCore>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncOptions {
    bootnode_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountOptions {
    network_passphrase: String,
    user_address: Option<String>,
    prover_worker_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyDisclosureOptions {
    prover_worker_url: Option<String>,
}

#[wasm_bindgen]
impl Client {
    /// Create a client shell (storage + RPC URL). Call [`Client::start_sync`]
    /// then [`Client::account`] before pool operations.
    #[wasm_bindgen(js_name = new)]
    pub fn new(storage: &Storage, rpc_url: String) -> Result<Client, JsError> {
        Ok(Self {
            rpc_url,
            storage: storage.fork(),
            core: None,
        })
    }

    /// Bundled deployment config (contract addresses, pools, network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config() -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
    }

    /// Probe wallet RPC retention. Returns `null` when sufficient, or a
    /// bootnode URL when historical sync requires one.
    #[wasm_bindgen(js_name = checkSync)]
    pub async fn check_sync(&self, options: JsValue) -> Result<JsValue, JsError> {
        let opts: SyncOptions = if options.is_null() || options.is_undefined() {
            SyncOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };
        let config = deployment_config()?;
        match events::bootnode_check(
            &self.rpc_url,
            self.storage.bridge(),
            config,
            opts.bootnode_url.as_deref(),
        )
        .await
        {
            Ok(None) => Ok(JsValue::NULL),
            Ok(Some(url)) => Ok(JsValue::from_str(&url)),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }

    /// Start background contract-event sync into local storage (idempotent per
    /// page).
    #[wasm_bindgen(js_name = startSync)]
    pub async fn start_sync(&self, options: JsValue) -> Result<(), JsError> {
        let opts: SyncOptions = if options.is_null() || options.is_undefined() {
            SyncOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };
        let config = deployment_config()?;
        events::start_indexer(
            self.rpc_url.clone(),
            opts.bootnode_url,
            self.storage.bridge(),
            config,
        )
        .await
    }

    /// Bind a wallet signer, spawn workers, derive privacy keys when missing,
    /// and return an [`Account`] session.
    pub async fn account(&mut self, options: JsValue, signer: JsValue) -> Result<Account, JsError> {
        let opts: AccountOptions = serde_wasm_bindgen::from_value(options)?;
        let user_address = resolve_user_address(&signer, opts.user_address).await?;
        let wallet_signer =
            WalletSigner::new(signer, opts.network_passphrase, user_address.clone())?;

        let core = self.ensure_core(opts.prover_worker_url).await?;

        if !core.user_keys_exist(&user_address).await? {
            let message = core.key_derivation_message();
            let sig_hex = wallet_signer.sign_wallet_message(&message).await?;
            let signature = crate::signer::wallet_message_signature_to_bytes(&sig_hex)?;
            core.derive_save_user_keys(user_address.clone(), signature)
                .await?;
        }

        Ok(Account::new(core, wallet_signer, user_address))
    }

    /// Look up a recipient's registered note and encryption public keys.
    #[wasm_bindgen(js_name = lookupRegisteredPublicKey)]
    pub async fn lookup_registered_public_key(&self, address: String) -> Result<JsValue, JsError> {
        if let Some(core) = &self.core {
            return core.lookup_registered_public_key(address).await;
        }

        let config = deployment_config()?;
        let req = StorageWorkerRequest::RecipientLookup {
            address,
            public_key_registry_contract_id: config.public_key_registry.clone(),
        };
        match self
            .storage
            .bridge()
            .call(req, 2_000)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?
        {
            StorageWorkerResponse::RecipientLookup(lookup) => {
                Ok(serde_wasm_bindgen::to_value(&lookup)?)
            }
            other => Err(JsError::new(&format!("unexpected response: {other:?}"))),
        }
    }

    /// On-chain ASP membership and non-membership state.
    #[wasm_bindgen(js_name = aspState)]
    pub async fn asp_state(&self) -> Result<JsValue, JsError> {
        if let Some(core) = &self.core {
            return core.asp_state().await;
        }

        let config = deployment_config()?;
        let fetcher = StateFetcher::new(&self.rpc_url, (*config).clone())
            .map_err(|e| JsError::new(&e.to_string()))?;
        let data = fetcher
            .asp_state()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        if let Some(core) = &self.core {
            return core.all_contracts_data().await;
        }

        let config = deployment_config()?;
        let fetcher = StateFetcher::new(&self.rpc_url, (*config).clone())
            .map_err(|e| JsError::new(&e.to_string()))?;
        let data = fetcher
            .all_contracts_data()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    /// Verify a selective-disclosure receipt without a wallet session.
    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &mut self,
        receipt_json: String,
        expected_vk_hash: String,
        options: JsValue,
    ) -> Result<JsValue, JsError> {
        let receipt: DisclosureReceipt = serde_json::from_str(&receipt_json)
            .map_err(|e| JsError::new(&format!("invalid receipt JSON: {e}")))?;
        let opts: VerifyDisclosureOptions = if options.is_null() || options.is_undefined() {
            VerifyDisclosureOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let core = self.ensure_core(opts.prover_worker_url).await?;
        let report = core
            .verify_selective_disclosure(&receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }
}

impl Client {
    async fn ensure_core(
        &mut self,
        prover_worker_url: Option<String>,
    ) -> Result<Rc<ClientCore>, JsError> {
        if let Some(core) = &self.core {
            return Ok(core.clone());
        }

        let core = Rc::new(
            ClientCore::connect(
                self.rpc_url.clone(),
                Some(self.storage.clone()),
                None,
                prover_worker_url,
            )
            .await?,
        );
        self.core = Some(core.clone());
        Ok(core)
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
