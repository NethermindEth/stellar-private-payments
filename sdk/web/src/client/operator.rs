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
    client::{
        envelope::{UnsignedOperatorCall, operator_err},
        gvk::GvkAudit,
        pool_err,
    },
    deployment::parse_contract_config,
    models::{AspMembership, AspNonMembership},
};

fn parse_field(value: &str, name: &str) -> Result<Field, JsValue> {
    Field::from_str(value.trim()).map_err(|e| JsError::new(&format!("{name}: {e}")).into())
}

fn parse_note_key(value: &str) -> Result<NotePublicKey, JsValue> {
    NotePublicKey::parse(value.trim())
        .map_err(|e| JsError::new(&format!("note public key {value}: {e}")).into())
}

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

/// Exposes the methods every contract handle shares, and the conversion from
/// its native handle.
macro_rules! contract_handle {
    ($handle:ident, $native:ident) => {
        impl From<$native> for $handle {
            fn from(inner: $native) -> Self {
                Self { inner }
            }
        }

        #[wasm_bindgen]
        impl $handle {
            /// Open a session over `rpcUrl` for `contractId`, listed in the
            /// deployment config or not, without a `Client` or local storage.
            #[wasm_bindgen(js_name = open)]
            pub fn open(
                rpc_url: String,
                contract_config: JsValue,
                contract_id: String,
            ) -> Result<$handle, JsError> {
                crate::wasm_start();
                let config = parse_contract_config(contract_config)?;
                Ok($native::open(&rpc_url, config, &contract_id)
                    .map_err(pool_err)?
                    .into())
            }

            #[wasm_bindgen(getter, js_name = contractId)]
            pub fn contract_id(&self) -> String {
                self.inner.contract_id().to_string()
            }

            /// Whether the deployment config lists the contract.
            #[wasm_bindgen(getter)]
            pub fn listed(&self) -> bool {
                self.inner.is_listed()
            }

            /// Admin and pending admin of the contract.
            pub async fn admin(&self) -> Result<AdminState, JsError> {
                Ok(self.inner.admin().await.map_err(pool_err)?.into())
            }

            /// Propose `newAdmin` (G… or C…), sourced by the current admin.
            /// The new admin takes over once it signs `acceptAdmin`. Builders
            /// refuse calls for a contract admin, which has to authorize its
            /// own.
            #[wasm_bindgen(js_name = proposeAdmin)]
            pub async fn propose_admin(
                &self,
                new_admin: String,
            ) -> Result<UnsignedOperatorCall, JsValue> {
                Ok(self
                    .inner
                    .propose_admin(&new_admin)
                    .await
                    .map_err(operator_err)?
                    .into())
            }

            /// Withdraw the pending admin transfer, sourced by the current
            /// admin.
            #[wasm_bindgen(js_name = cancelAdminTransfer)]
            pub async fn cancel_admin_transfer(&self) -> Result<UnsignedOperatorCall, JsValue> {
                Ok(self
                    .inner
                    .cancel_admin_transfer()
                    .await
                    .map_err(operator_err)?
                    .into())
            }

            /// Complete the pending admin transfer, sourced by the pending
            /// admin.
            #[wasm_bindgen(js_name = acceptAdmin)]
            pub async fn accept_admin(&self) -> Result<UnsignedOperatorCall, JsValue> {
                Ok(self
                    .inner
                    .accept_admin()
                    .await
                    .map_err(operator_err)?
                    .into())
            }
        }
    };
}

contract_handle!(AllowlistOperator, NativeAllowlistOperator);
contract_handle!(BlocklistOperator, NativeBlocklistOperator);
contract_handle!(PoolAdmin, NativePoolAdmin);

/// Session for the admin of one membership tree.
///
/// Open with `client.allowlistOperator(contractId)`, or without a client with
/// `AllowlistOperator.open(rpcUrl, contractConfig, contractId)`.
#[wasm_bindgen]
pub struct AllowlistOperator {
    inner: NativeAllowlistOperator,
}

#[wasm_bindgen]
impl AllowlistOperator {
    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspMembership, JsError> {
        Ok(self.inner.state().await.map_err(pool_err)?.into())
    }

    /// Append `leaf` (`0x` hex), sourced by the tree's admin.
    #[wasm_bindgen(js_name = insertLeaf)]
    pub async fn insert_leaf(&self, leaf: String) -> Result<UnsignedOperatorCall, JsValue> {
        let leaf = parse_field(&leaf, "leaf")?;
        Ok(self
            .inner
            .insert_leaf(leaf)
            .await
            .map_err(operator_err)?
            .into())
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

/// Session for the admin of one non-membership tree.
///
/// Open with `client.blocklistOperator(contractId)`, or without a client with
/// `BlocklistOperator.open(rpcUrl, contractConfig, contractId)`.
#[wasm_bindgen]
pub struct BlocklistOperator {
    inner: NativeBlocklistOperator,
}

#[wasm_bindgen]
impl BlocklistOperator {
    /// On-chain state of the tree.
    pub async fn state(&self) -> Result<AspNonMembership, JsError> {
        Ok(self.inner.state().await.map_err(pool_err)?.into())
    }

    /// Block note public keys (`0x` hex), sourced by the tree's admin.
    /// Repeats are dropped.
    #[wasm_bindgen(js_name = insertKeys)]
    pub async fn insert_keys(
        &self,
        note_keys: Vec<String>,
    ) -> Result<UnsignedOperatorCall, JsValue> {
        let keys = note_keys
            .iter()
            .map(|key| parse_note_key(key))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self
            .inner
            .insert_keys(&keys)
            .await
            .map_err(operator_err)?
            .into())
    }

    /// Unblock a note public key (`0x` hex), sourced by the tree's admin.
    #[wasm_bindgen(js_name = deleteKey)]
    pub async fn delete_key(&self, note_key: String) -> Result<UnsignedOperatorCall, JsValue> {
        let key = parse_note_key(&note_key)?;
        Ok(self
            .inner
            .delete_key(&key)
            .await
            .map_err(operator_err)?
            .into())
    }
}

/// Session for the admin of one pool.
///
/// Open with `client.poolAdmin(contractId)`, or without a client with
/// `PoolAdmin.open(rpcUrl, contractConfig, contractId)`.
#[wasm_bindgen]
pub struct PoolAdmin {
    inner: NativePoolAdmin,
}

#[wasm_bindgen]
impl PoolAdmin {
    /// Point the pool at membership tree `tree`, sourced by the pool admin.
    #[wasm_bindgen(js_name = repointAllowlist)]
    pub async fn repoint_allowlist(&self, tree: String) -> Result<UnsignedOperatorCall, JsValue> {
        Ok(self
            .inner
            .repoint_allowlist(&tree)
            .await
            .map_err(operator_err)?
            .into())
    }

    /// Point the pool at non-membership tree `tree`, sourced by the pool
    /// admin.
    #[wasm_bindgen(js_name = repointBlocklist)]
    pub async fn repoint_blocklist(&self, tree: String) -> Result<UnsignedOperatorCall, JsValue> {
        Ok(self
            .inner
            .repoint_blocklist(&tree)
            .await
            .map_err(operator_err)?
            .into())
    }

    /// Stop deposits; transfers and withdrawals continue.
    #[wasm_bindgen(js_name = pauseDeposits)]
    pub async fn pause_deposits(&self) -> Result<UnsignedOperatorCall, JsValue> {
        Ok(self
            .inner
            .pause_deposits()
            .await
            .map_err(operator_err)?
            .into())
    }

    #[wasm_bindgen(js_name = unpauseDeposits)]
    pub async fn unpause_deposits(&self) -> Result<UnsignedOperatorCall, JsValue> {
        Ok(self
            .inner
            .unpause_deposits()
            .await
            .map_err(operator_err)?
            .into())
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
