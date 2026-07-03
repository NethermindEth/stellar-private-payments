//! Wasm [`Client`] — `new` → `startSync` → `initialize`, then pool
//! factory.

use std::rc::Rc;

use serde::Deserialize;
use stellar_private_payments_sdk::types::DisclosureReceipt;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use crate::{
    deployment::deployment_config,
    events,
    protocol::{StorageWorkerRequest, StorageWorkerResponse},
    signer::WalletSigner,
    storage::Storage,
};

use super::{core::ClientCore, pool_err};

use super::pool::{PoolCreateConfig, PrivatePool};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SyncOptions {
    bootnode_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitializeOptions {
    network_passphrase: String,
    user_address: Option<String>,
    prover_worker_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PoolOptions {
    pool_contract: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyDisclosureOptions {
    prover_worker_url: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeysOptions {
    note_public_key_hex: Option<String>,
    encryption_public_key_hex: Option<String>,
}

/// Browser SDK session for one Stellar account (workers, RPC, wallet signer).
#[wasm_bindgen]
pub struct Client {
    rpc_url: String,
    storage: Storage,
    core: Option<Rc<ClientCore>>,
    signer: Option<WalletSigner>,
    user_address: Option<String>,
}

#[wasm_bindgen]
impl Client {
    /// Create a client shell (storage + RPC URL). Call
    /// [`Client::start_sync`] then [`Client::initialize`] before pool
    /// or account operations.
    #[wasm_bindgen(js_name = new)]
    pub fn new(storage: &Storage, rpc_url: String) -> Result<Client, JsError> {
        Ok(Self {
            rpc_url,
            storage: storage.fork(),
            core: None,
            signer: None,
            user_address: None,
        })
    }

    /// Bundled deployment config (contract addresses, pools, network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config() -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
    }

    /// Probe wallet RPC retention. Returns `null` when sufficient, or a
    /// bootnode URL when historical sync requires one.
    ///
    /// Throws when the RPC has a sync gap and no bootnode URL is available
    /// (message contains `RPC_SYNC_GAP`).
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

    /// Bind a wallet signer, spawn workers, and derive privacy keys when
    /// missing.
    pub async fn initialize(&mut self, options: JsValue, signer: JsValue) -> Result<(), JsError> {
        if self.core.is_some() {
            return Err(JsError::new("client already initialized"));
        }

        let opts: InitializeOptions = serde_wasm_bindgen::from_value(options)?;
        let user_address = resolve_user_address(&signer, opts.user_address).await?;
        let wallet_signer =
            WalletSigner::new(signer, opts.network_passphrase, user_address.clone())?;

        let core = Rc::new(
            ClientCore::connect(
                self.rpc_url.clone(),
                Some(self.storage.clone()),
                None,
                opts.prover_worker_url,
            )
            .await?,
        );

        if !core.user_keys_exist(&user_address).await? {
            let message = core.key_derivation_message();
            let sig_hex = wallet_signer.sign_wallet_message(&message).await?;
            let signature = crate::signer::wallet_message_signature_to_bytes(&sig_hex)?;
            core.derive_save_user_keys(user_address.clone(), signature)
                .await?;
        }

        self.core = Some(core);
        self.signer = Some(wallet_signer);
        self.user_address = Some(user_address);
        Ok(())
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        self.session()?.0.all_contracts_data().await
    }

    /// Register this account's public keys on the deployment-wide registry.
    ///
    /// `options` may omit key hex strings to use keys from local storage after
    /// [`Client::initialize`].
    #[wasm_bindgen(js_name = registerPublicKeys)]
    pub async fn register_public_keys(&self, options: JsValue) -> Result<String, JsError> {
        let (core, signer, user_address) = self.session()?;
        let opts: RegisterPublicKeysOptions = if options.is_null() || options.is_undefined() {
            RegisterPublicKeysOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let (note_public_key_hex, encryption_public_key_hex) = match (
            opts.note_public_key_hex,
            opts.encryption_public_key_hex,
        ) {
            (Some(note), Some(enc)) => (note, enc),
            (None, None) => core.user_public_keys_hex(user_address).await?,
            _ => {
                return Err(JsError::new(
                    "notePublicKeyHex and encryptionPublicKeyHex must both be set or both omitted",
                ));
            }
        };

        core.register_public_keys(
            signer,
            user_address.to_string(),
            note_public_key_hex,
            encryption_public_key_hex,
        )
        .await
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

    /// Verify a selective-disclosure receipt without a wallet session.
    ///
    /// Spawns the prover worker on demand when [`Client::initialize`] has not
    /// been called (e.g. the disclosure verify page).
    #[wasm_bindgen(js_name = verifySelectiveDisclosure)]
    pub async fn verify_selective_disclosure(
        &self,
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

        let core = if let Some(core) = &self.core {
            core.clone()
        } else {
            Rc::new(
                ClientCore::connect(
                    self.rpc_url.clone(),
                    Some(self.storage.clone()),
                    None,
                    opts.prover_worker_url,
                )
                .await?,
            )
        };

        let report = core
            .verify_selective_disclosure(&receipt, &expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }

    /// Open a private pool session for this account.
    pub async fn pool(&self, options: JsValue) -> Result<PrivatePool, JsError> {
        let (core, signer, user_address) = self.session()?;
        let opts: PoolOptions = serde_wasm_bindgen::from_value(options)?;
        let pool_cfg = PoolCreateConfig {
            pool_contract: opts.pool_contract,
            user_address: user_address.to_string(),
        };
        let inner = Rc::new(core.create_pool_internal(&pool_cfg, signer).await?);
        Ok(PrivatePool::from_parts(
            inner,
            core.clone(),
            user_address.to_string(),
        ))
    }
}

impl Client {
    fn session(&self) -> Result<(&Rc<ClientCore>, &WalletSigner, &str), JsError> {
        let core = self
            .core
            .as_ref()
            .ok_or_else(|| JsError::new("call initialize() first"))?;
        let signer = self
            .signer
            .as_ref()
            .ok_or_else(|| JsError::new("call initialize() first"))?;
        let user_address = self
            .user_address
            .as_ref()
            .ok_or_else(|| JsError::new("call initialize() first"))?;
        Ok((core, signer, user_address))
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
