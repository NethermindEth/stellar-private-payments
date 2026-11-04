//! Sync wrappers around the [`crate::operator`] handles.

use crate::{
    Error,
    gvk::{GvkAudit as AsyncGvkAudit, GvkTxAudit},
    operator::{
        AdminState, AllowlistOperator as AsyncAllowlistOperator,
        BlocklistOperator as AsyncBlocklistOperator, GvkAuthority as AsyncGvkAuthority,
        PoolAdmin as AsyncPoolAdmin,
    },
    types::{AspMembership, AspNonMembership, ContractConfig},
};

use super::runtime::block_on;

/// Blocking wrapper around [`crate::operator::AllowlistOperator`].
pub struct AllowlistOperator {
    inner: AsyncAllowlistOperator,
}

impl AllowlistOperator {
    pub fn open(
        rpc_url: &str,
        contract_config: ContractConfig,
        contract_id: &str,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncAllowlistOperator::open(rpc_url, contract_config, contract_id)?,
        })
    }

    pub fn contract_id(&self) -> &str {
        self.inner.contract_id()
    }

    pub fn state(&self) -> Result<AspMembership, Error> {
        block_on(self.inner.state())
    }

    pub fn admin(&self) -> Result<AdminState, Error> {
        block_on(self.inner.admin())
    }
}

/// Blocking wrapper around [`crate::operator::BlocklistOperator`].
pub struct BlocklistOperator {
    inner: AsyncBlocklistOperator,
}

impl BlocklistOperator {
    pub fn open(
        rpc_url: &str,
        contract_config: ContractConfig,
        contract_id: &str,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncBlocklistOperator::open(rpc_url, contract_config, contract_id)?,
        })
    }

    pub fn contract_id(&self) -> &str {
        self.inner.contract_id()
    }

    pub fn state(&self) -> Result<AspNonMembership, Error> {
        block_on(self.inner.state())
    }

    pub fn admin(&self) -> Result<AdminState, Error> {
        block_on(self.inner.admin())
    }
}

/// Blocking wrapper around [`crate::operator::PoolAdmin`].
pub struct PoolAdmin {
    inner: AsyncPoolAdmin,
}

impl PoolAdmin {
    pub fn open(
        rpc_url: &str,
        contract_config: ContractConfig,
        contract_id: &str,
    ) -> Result<Self, Error> {
        Ok(Self {
            inner: AsyncPoolAdmin::open(rpc_url, contract_config, contract_id)?,
        })
    }

    pub fn contract_id(&self) -> &str {
        self.inner.contract_id()
    }

    pub fn admin(&self) -> Result<AdminState, Error> {
        block_on(self.inner.admin())
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
