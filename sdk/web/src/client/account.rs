//! Wasm [`Account`] — wallet session bound to a [`super::Client`].

use std::rc::Rc;

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::signer::WalletSigner;

use super::{
    core::ClientCore,
    pool::{PoolCreateConfig, PrivatePool},
};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeysOptions {
    note_public_key_hex: Option<String>,
    encryption_public_key_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PoolOptions {
    pool_contract: String,
}

/// Wallet session for one Stellar account. Construct via
/// [`super::Client::account`].
#[wasm_bindgen]
pub struct Account {
    core: Rc<ClientCore>,
    signer: WalletSigner,
    user_address: String,
}

impl Account {
    pub(crate) fn new(core: Rc<ClientCore>, signer: WalletSigner, user_address: String) -> Self {
        Self {
            core,
            signer,
            user_address,
        }
    }
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(getter, js_name = userAddress)]
    pub fn user_address(&self) -> String {
        self.user_address.clone()
    }

    /// On-chain state for all enabled pools plus shared ASP contracts.
    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        self.core.all_contracts_data().await
    }

    /// Register this account's public keys on the deployment-wide registry.
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
        Ok(PrivatePool::from_parts(inner, self.user_address.clone()))
    }
}
