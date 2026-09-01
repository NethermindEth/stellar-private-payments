//! Wasm [`Account`] — wallet session wrapping the native SDK [`NativeAccount`].

use std::rc::Rc;

use stellar_private_payments::{
    Account as NativeAccount,
    types::{EncryptionPublicKey, NotePublicKey},
};

use wasm_bindgen::prelude::*;

use crate::{
    models::{
        PoolOptions, PortfolioBalance, RegisterPublicKeysOptions, UserNoteSummary, UserPublicKeys,
        portfolio_balances, user_note_summaries,
    },
    workers::storage::StorageBridge,
};

use super::{pool::PrivatePool, pool_err};

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
    /// The account that owns the notes.
    #[wasm_bindgen(getter, js_name = userAddress)]
    pub fn user_address(&self) -> String {
        self.inner.user_address().to_string()
    }

    /// The account that signs and pays. Equal to [`Self::user_address`] until
    /// a caller supplies a different `signerAddress`.
    #[wasm_bindgen(getter, js_name = signerAddress)]
    pub fn signer_address(&self) -> String {
        self.inner.signer_address().to_string()
    }

    /// Portfolio balances across all enabled pools in the deployment.
    pub async fn portfolio(&self) -> Result<Vec<PortfolioBalance>, JsError> {
        let portfolio = self.inner.portfolio().await.map_err(pool_err)?;
        Ok(portfolio_balances(portfolio))
    }

    /// Locally derived note and encryption public keys for this account.
    #[wasm_bindgen(js_name = userPublicKeys)]
    pub async fn user_public_keys(&self) -> Result<UserPublicKeys, JsError> {
        let keys = self.inner.user_public_keys().await.map_err(pool_err)?;
        Ok(UserPublicKeys::from(keys))
    }

    /// Notes for this account across all pools (newest first).
    #[wasm_bindgen(js_name = userNotes)]
    pub async fn user_notes(&self, limit: u32) -> Result<Vec<UserNoteSummary>, JsError> {
        let notes = self.inner.user_notes(limit).await.map_err(pool_err)?;
        Ok(user_note_summaries(notes))
    }

    /// Locally derived ASP membership blinding for this account.
    #[wasm_bindgen(js_name = aspSecret)]
    pub async fn asp_secret(&self) -> Result<String, JsError> {
        let secret = self.inner.asp_secret().await.map_err(pool_err)?;
        Ok(secret.to_string())
    }

    /// Derive the ASP membership tree leaf for this account's stored keys.
    ///
    /// For explicit inputs without a session, use the free
    /// [`derive_asp_user_leaf`](super::derive_asp_user_leaf) export.
    #[wasm_bindgen(js_name = deriveAspUserLeaf)]
    pub async fn derive_asp_user_leaf(&self) -> Result<String, JsError> {
        let leaf = self.inner.derive_asp_user_leaf().await.map_err(pool_err)?;
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
        let opts = RegisterPublicKeysOptions::from_value(options)?;

        let (note_public_key, encryption_public_key) = match (
            opts.note_public_key_hex(),
            opts.encryption_public_key_hex(),
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
        let opts = PoolOptions::from_value(options)?;
        let inner = Rc::new(self.inner.pool(opts.pool_contract()).map_err(pool_err)?);
        Ok(PrivatePool::from_parts(
            inner,
            self.inner.user_address().to_string(),
        ))
    }
}
