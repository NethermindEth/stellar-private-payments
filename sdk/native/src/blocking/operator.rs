//! Sync wrappers around the [`crate::operator`] handles.

use crate::{
    Error,
    gvk::{GvkAudit as AsyncGvkAudit, GvkTxAudit},
    operator::{
        AdminState, AllowlistOperator as AsyncAllowlistOperator,
        BlocklistOperator as AsyncBlocklistOperator, CallState, CallStatus,
        Envelopes as AsyncEnvelopes, GvkAuthority as AsyncGvkAuthority, OperatorCall,
        PoolAdmin as AsyncPoolAdmin, PoolLists, SigningStatus, UnsignedOperatorCall,
    },
    types::{AspMembership, AspNonMembership, ContractConfig, Field, NotePublicKey},
};

use super::runtime::block_on;

/// Defines the blocking wrapper of a contract handle with the methods every
/// contract handle shares.
macro_rules! blocking_contract_handle {
    ($handle:ident, $inner:ident) => {
        #[doc = concat!("Blocking wrapper around [`crate::operator::", stringify!($handle), "`].")]
        pub struct $handle {
            inner: $inner,
        }

        impl $handle {
            pub fn open(
                rpc_url: &str,
                contract_config: ContractConfig,
                contract_id: &str,
            ) -> Result<Self, Error> {
                Ok(Self {
                    inner: $inner::open(rpc_url, contract_config, contract_id)?,
                })
            }

            pub(crate) fn from_inner(inner: $inner) -> Self {
                Self { inner }
            }

            pub fn contract_id(&self) -> &str {
                self.inner.contract_id()
            }

            pub fn is_listed(&self) -> bool {
                self.inner.is_listed()
            }

            pub fn admin(&self) -> Result<AdminState, Error> {
                block_on(self.inner.admin())
            }

            pub fn pending_admin(&self) -> Result<Option<String>, Error> {
                block_on(self.inner.pending_admin())
            }

            pub fn propose_admin(&self, new_admin: &str) -> Result<UnsignedOperatorCall, Error> {
                block_on(self.inner.propose_admin(new_admin))
            }

            pub fn cancel_admin_transfer(&self) -> Result<UnsignedOperatorCall, Error> {
                block_on(self.inner.cancel_admin_transfer())
            }

            pub fn accept_admin(&self) -> Result<UnsignedOperatorCall, Error> {
                block_on(self.inner.accept_admin())
            }
        }
    };
}

blocking_contract_handle!(AllowlistOperator, AsyncAllowlistOperator);
blocking_contract_handle!(BlocklistOperator, AsyncBlocklistOperator);
blocking_contract_handle!(PoolAdmin, AsyncPoolAdmin);

impl AllowlistOperator {
    pub fn state(&self) -> Result<AspMembership, Error> {
        block_on(self.inner.state())
    }

    pub fn insert_leaf(&self, leaf: Field) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.insert_leaf(leaf))
    }
}

impl BlocklistOperator {
    pub fn state(&self) -> Result<AspNonMembership, Error> {
        block_on(self.inner.state())
    }

    pub fn insert_keys(&self, note_keys: &[NotePublicKey]) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.insert_keys(note_keys))
    }

    pub fn delete_key(&self, note_key: &NotePublicKey) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.delete_key(note_key))
    }
}

/// Blocking [`crate::operator::pool_lists`].
pub fn pool_lists(rpc_url: &str, pools: &[String]) -> Result<Vec<PoolLists>, Error> {
    block_on(crate::operator::pool_lists(rpc_url, pools))
}

impl PoolAdmin {
    pub fn lists(&self) -> Result<PoolLists, Error> {
        block_on(self.inner.lists())
    }

    pub fn repoint_allowlist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.repoint_allowlist(tree))
    }

    pub fn repoint_blocklist(&self, tree: &str) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.repoint_blocklist(tree))
    }

    pub fn pause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.pause_deposits())
    }

    pub fn unpause_deposits(&self) -> Result<UnsignedOperatorCall, Error> {
        block_on(self.inner.unpause_deposits())
    }
}

/// Blocking wrapper around [`crate::operator::Envelopes`].
pub struct Envelopes {
    inner: AsyncEnvelopes,
}

impl Envelopes {
    pub fn open(rpc_url: &str, network_passphrase: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncEnvelopes::open(rpc_url, network_passphrase)?,
        })
    }

    pub fn describe(&self, envelope_xdr: &str) -> Result<OperatorCall, Error> {
        self.inner.describe(envelope_xdr)
    }

    pub fn signing_status(&self, envelope_xdr: &str) -> Result<SigningStatus, Error> {
        block_on(self.inner.signing_status(envelope_xdr))
    }

    pub fn state(&self, envelope_xdr: &str) -> Result<CallState, Error> {
        block_on(self.inner.state(envelope_xdr))
    }

    pub fn submit(&self, signed_envelope_xdr: &str) -> Result<String, Error> {
        block_on(self.inner.submit(signed_envelope_xdr))
    }

    pub fn confirm(&self, hash: &str) -> Result<CallStatus, Error> {
        block_on(self.inner.confirm(hash))
    }
}

/// Blocking wrapper around [`crate::operator::GvkAuthority`].
pub struct GvkAuthority {
    inner: AsyncGvkAuthority,
}

impl GvkAuthority {
    pub(crate) fn from_inner(inner: AsyncGvkAuthority) -> Self {
        Self { inner }
    }

    pub fn audit(&self, pool_contract_id: &str) -> Result<GvkAudit, Error> {
        Ok(GvkAudit {
            inner: block_on(self.inner.audit(pool_contract_id))?,
        })
    }
}

/// Blocking wrapper around [`crate::gvk::GvkAudit`].
pub struct GvkAudit {
    inner: AsyncGvkAudit,
}

impl GvkAudit {
    pub fn pool_contract_id(&self) -> &str {
        self.inner.pool_contract_id()
    }

    /// The next audited transact, or `None` once the indexed events are
    /// exhausted.
    pub fn next_tx(&mut self) -> Result<Option<GvkTxAudit>, Error> {
        Ok(block_on(self.inner.next_tx())?)
    }
}
