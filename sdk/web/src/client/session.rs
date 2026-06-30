//! Wasm [`Client`] — one account session (workers + signer) and pool factory.

use std::rc::Rc;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::{deployment::deployment_config, signer::WalletSigner};

use super::core::ClientCore;

use super::pool::{PoolCreateConfig, PrivatePool};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectOptions {
    rpc_url: String,
    network_passphrase: String,
    user_address: String,
    storage_worker_url: Option<String>,
    prover_worker_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PoolOptions {
    pool_contract: String,
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
    core: Rc<ClientCore>,
    signer: WalletSigner,
    user_address: String,
}

#[wasm_bindgen]
impl Client {
    /// Connect workers and bind a wallet signer for this account session.
    #[wasm_bindgen(js_name = connect)]
    pub async fn connect(options: JsValue, signer: JsValue) -> Result<Client, JsError> {
        let opts: ConnectOptions = serde_wasm_bindgen::from_value(options)?;
        let wallet_signer =
            WalletSigner::new(signer, opts.network_passphrase, opts.user_address.clone())?;
        let core = Rc::new(
            ClientCore::connect(
                opts.rpc_url,
                opts.storage_worker_url,
                opts.prover_worker_url,
            )
            .await?,
        );
        Ok(Self {
            core,
            signer: wallet_signer,
            user_address: opts.user_address,
        })
    }

    /// Bundled deployment config (contract addresses, pools, network).
    #[wasm_bindgen(js_name = contractConfig)]
    pub fn contract_config() -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        self.core.all_contracts_data().await
    }

    /// Derive privacy keys from the bound wallet signature and persist locally.
    pub async fn initialize(&self) -> Result<(), JsError> {
        let message = self.core.key_derivation_message();
        let sig_hex = self.signer.sign_wallet_message(&message).await?;
        let signature = crate::signer::hex_signature_to_bytes(&sig_hex)?;
        self.core
            .derive_save_user_keys(self.user_address.clone(), signature)
            .await
    }

    /// Register this account's public keys on the deployment-wide registry.
    ///
    /// `options` may omit key hex strings to use keys from local storage after
    /// [`Client::initialize`].
    #[wasm_bindgen(js_name = registerPublicKeys)]
    pub async fn register_public_keys(&self, options: JsValue) -> Result<String, JsError> {
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
            (None, None) => self.core.user_public_keys_hex(&self.user_address).await?,
            _ => {
                return Err(JsError::new(
                    "notePublicKeyHex and encryptionPublicKeyHex must both be set or both omitted",
                ));
            }
        };

        self.core
            .register_public_keys(
                &self.signer,
                self.user_address.clone(),
                note_public_key_hex,
                encryption_public_key_hex,
            )
            .await
    }

    /// Look up a recipient's registered note and encryption public keys.
    #[wasm_bindgen(js_name = lookupRegisteredPublicKey)]
    pub async fn lookup_registered_public_key(&self, address: String) -> Result<JsValue, JsError> {
        self.core.lookup_registered_public_key(address).await
    }

    /// Open a private pool session for this account.
    pub async fn pool(&self, options: JsValue) -> Result<PrivatePool, JsError> {
        let opts: PoolOptions = serde_wasm_bindgen::from_value(options)?;
        let pool_cfg = PoolCreateConfig {
            pool_contract: opts.pool_contract,
            user_address: self.user_address.clone(),
        };
        let inner = Rc::new(
            self.core
                .create_pool_internal(&pool_cfg, &self.signer)
                .await?,
        );
        Ok(PrivatePool::from_parts(
            inner,
            self.core.clone(),
            self.user_address.clone(),
        ))
    }
}
