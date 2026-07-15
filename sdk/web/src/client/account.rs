//! Wasm [`Account`] — wallet session wrapping the native SDK [`NativeAccount`].

use std::rc::Rc;

use serde::Deserialize;
use stellar_private_payments_sdk::{
    Account as NativeAccount,
    types::{EncryptionPublicKey, NotePublicKey},
};
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

use super::{pool::PrivatePool, pool_err};

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
    inner: Rc<NativeAccount<StorageBridge>>,
}

impl Account {
    pub(crate) fn new(inner: Rc<NativeAccount<StorageBridge>>) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(getter, js_name = userAddress)]
    pub fn user_address(&self) -> String {
        self.inner.user_address().to_string()
    }

    /// Portfolio balances across all enabled pools in the deployment.
    pub async fn portfolio(&self) -> Result<JsValue, JsError> {
        let portfolio = self.inner.portfolio().await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&portfolio)?)
    }

    /// Register this account's public keys on the deployment-wide registry.
    #[wasm_bindgen(js_name = registerPublicKeys)]
    pub async fn register_public_keys(&self, options: JsValue) -> Result<String, JsError> {
        let opts: RegisterPublicKeysOptions = if options.is_null() || options.is_undefined() {
            RegisterPublicKeysOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let (note_public_key, encryption_public_key) = match (
            opts.note_public_key_hex,
            opts.encryption_public_key_hex,
        ) {
            (Some(note), Some(enc)) => (
                Some(NotePublicKey::parse(&note).map_err(|e| JsError::new(&e.to_string()))?),
                Some(EncryptionPublicKey::parse(&enc).map_err(|e| JsError::new(&e.to_string()))?),
            ),
            (None, None) => (None, None),
            _ => {
                return Err(JsError::new(
                    "notePublicKeyHex and encryptionPublicKeyHex must both be set or both omitted",
                ));
            }
        };

        let result = self
            .inner
            .register_public_keys(note_public_key, encryption_public_key)
            .await
            .map_err(pool_err)?;
        Ok(result.tx_hash)
    }

    /// Open a private pool session for this account.
    pub async fn pool(&self, options: JsValue) -> Result<PrivatePool, JsError> {
        let opts: PoolOptions = serde_wasm_bindgen::from_value(options)?;
        let inner = Rc::new(self.inner.pool(opts.pool_contract).map_err(pool_err)?);
        Ok(PrivatePool::from_parts(
            inner,
            self.inner.user_address().to_string(),
        ))
    }
}
