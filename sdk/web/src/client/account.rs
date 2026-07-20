//! Wasm [`Account`] — wallet session wrapping the native SDK [`NativeAccount`].

use std::rc::Rc;

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use stellar_private_payments_sdk::{
    Account as NativeAccount,
    types::{EncryptionPublicKey, Field, NotePublicKey},
};

use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

use super::{pool::PrivatePool, pool_err};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserPublicKeysOut {
    note_public_key: NotePublicKey,
    encryption_public_key: EncryptionPublicKey,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeysOptions {
    note_public_key_hex: Option<String>,
    encryption_public_key_hex: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeriveAspUserLeafOptions {
    note_public_key: Option<String>,
    membership_blinding: Option<String>,
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

    /// Locally derived note and encryption public keys for this account.
    #[wasm_bindgen(js_name = userPublicKeys)]
    pub async fn user_public_keys(&self) -> Result<JsValue, JsError> {
        let (note, enc) = self.inner.user_public_keys().await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&UserPublicKeysOut {
            note_public_key: note,
            encryption_public_key: enc,
        })?)
    }

    /// Notes for this account across all pools (newest first).
    #[wasm_bindgen(js_name = userNotes)]
    pub async fn user_notes(&self, limit: u32) -> Result<JsValue, JsError> {
        let notes = self.inner.user_notes(limit).await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&notes)?)
    }

    /// Locally derived ASP membership blinding for this account.
    #[wasm_bindgen(js_name = aspSecret)]
    pub async fn asp_secret(&self) -> Result<String, JsError> {
        let secret = self.inner.asp_secret().await.map_err(pool_err)?;
        Ok(secret.to_string())
    }

    /// Derive the ASP membership tree leaf for this account's note public key.
    #[wasm_bindgen(js_name = deriveAspUserLeaf)]
    pub async fn derive_asp_user_leaf(&self, options: JsValue) -> Result<String, JsError> {
        let opts: DeriveAspUserLeafOptions = if options.is_null() || options.is_undefined() {
            DeriveAspUserLeafOptions::default()
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        let note_public_key = match opts.note_public_key {
            Some(raw) => {
                Some(NotePublicKey::parse(&raw).map_err(|e| JsError::new(&e.to_string()))?)
            }
            None => None,
        };
        let membership_blinding = match opts.membership_blinding {
            Some(raw) => Some(Field::from_str(&raw).map_err(|e| JsError::new(&e.to_string()))?),
            None => None,
        };

        let leaf = self
            .inner
            .derive_asp_user_leaf(note_public_key, membership_blinding)
            .await
            .map_err(pool_err)?;
        Ok(leaf.to_string())
    }

    /// Whether this account's public keys are registered on-chain.
    #[wasm_bindgen(js_name = isRegistered)]
    pub async fn is_registered(&self) -> Result<bool, JsError> {
        self.inner.is_registered().await.map_err(pool_err)
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
