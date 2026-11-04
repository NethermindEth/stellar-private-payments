//! Wasm wrappers around the native operator handles.

use std::str::FromStr;

use stellar_private_payments::{
    operator::{
        AdminState as NativeAdminState, AllowlistOperator as NativeAllowlistOperator,
        BlocklistOperator as NativeBlocklistOperator, GvkAuthority as NativeGvkAuthority,
        PoolAdmin as NativePoolAdmin, derive_asp_user_leaf,
    },
    types::{Field, NotePublicKey},
};
use wasm_bindgen::prelude::*;

use crate::{
    client::{gvk::GvkAudit, pool_err},
    models::{AspMembership, AspNonMembership},
};

/// A contract's admin and the admin proposed to replace it.
#[wasm_bindgen]
pub struct AdminState {
    inner: NativeAdminState,
}

#[wasm_bindgen]
impl AdminState {
    #[wasm_bindgen(getter)]
    pub fn admin(&self) -> String {
        self.inner.admin.clone()
    }

    /// Set between `update_admin` and `accept_admin` or
    /// `cancel_admin_transfer`.
    #[wasm_bindgen(getter, js_name = pendingAdmin)]
    pub fn pending_admin(&self) -> Option<String> {
        self.inner.pending_admin.clone()
    }
}

impl From<NativeAdminState> for AdminState {
    fn from(inner: NativeAdminState) -> Self {
        Self { inner }
    }
}

/// Session for the admin of one membership tree.
///
/// Open with `client.allowlistOperator(contractId)`.
#[wasm_bindgen]
pub struct AllowlistOperator {
    inner: NativeAllowlistOperator,
}

#[wasm_bindgen]
impl AllowlistOperator {
    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id().to_string()
    }

    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspMembership, JsError> {
        Ok(self.inner.state().await.map_err(pool_err)?.into())
    }

    /// Admin and pending admin of the tree.
    pub async fn admin(&self) -> Result<AdminState, JsError> {
        Ok(self.inner.admin().await.map_err(pool_err)?.into())
    }

    /// Derive the membership leaf of a user from their note public key and
    /// membership blinding, both `0x` hex.
    #[wasm_bindgen(js_name = deriveUserLeaf)]
    pub fn derive_user_leaf(
        note_public_key: String,
        membership_blinding: String,
    ) -> Result<String, JsError> {
        let note =
            NotePublicKey::parse(&note_public_key).map_err(|e| JsError::new(&e.to_string()))?;
        let blinding =
            Field::from_str(&membership_blinding).map_err(|e| JsError::new(&e.to_string()))?;
        let leaf = derive_asp_user_leaf(&note, &blinding).map_err(pool_err)?;
        Ok(leaf.to_string())
    }
}

impl From<NativeAllowlistOperator> for AllowlistOperator {
    fn from(inner: NativeAllowlistOperator) -> Self {
        Self { inner }
    }
}

/// Session for the admin of one non-membership tree.
///
/// Open with `client.blocklistOperator(contractId)`.
#[wasm_bindgen]
pub struct BlocklistOperator {
    inner: NativeBlocklistOperator,
}

#[wasm_bindgen]
impl BlocklistOperator {
    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id().to_string()
    }

    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspNonMembership, JsError> {
        Ok(self.inner.state().await.map_err(pool_err)?.into())
    }

    /// Admin and pending admin of the tree.
    pub async fn admin(&self) -> Result<AdminState, JsError> {
        Ok(self.inner.admin().await.map_err(pool_err)?.into())
    }
}

impl From<NativeBlocklistOperator> for BlocklistOperator {
    fn from(inner: NativeBlocklistOperator) -> Self {
        Self { inner }
    }
}

/// Session for the admin of one pool.
///
/// Open with `client.poolAdmin(contractId)`.
#[wasm_bindgen]
pub struct PoolAdmin {
    inner: NativePoolAdmin,
}

#[wasm_bindgen]
impl PoolAdmin {
    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> String {
        self.inner.contract_id().to_string()
    }

    /// Admin and pending admin of the pool.
    pub async fn admin(&self) -> Result<AdminState, JsError> {
        Ok(self.inner.admin().await.map_err(pool_err)?.into())
    }
}

impl From<NativePoolAdmin> for PoolAdmin {
    fn from(inner: NativePoolAdmin) -> Self {
        Self { inner }
    }
}

/// Session for the holder of a Global View Key private key.
///
/// Holds the key for its lifetime; free it when finished.
/// Open with `client.gvkAuthority(globalViewPrivateKeyHex)`.
#[wasm_bindgen]
pub struct GvkAuthority {
    inner: NativeGvkAuthority,
}

#[wasm_bindgen]
impl GvkAuthority {
    /// Sync local storage, then open an audit cursor over a pool's private
    /// transacts. Requires a pool-gvk pool configured with this key.
    pub async fn audit(&self, pool_contract_id: String) -> Result<GvkAudit, JsError> {
        let audit = self
            .inner
            .audit(&pool_contract_id)
            .await
            .map_err(pool_err)?;
        Ok(GvkAudit::new(audit))
    }
}

impl From<NativeGvkAuthority> for GvkAuthority {
    fn from(inner: NativeGvkAuthority) -> Self {
        Self { inner }
    }
}
