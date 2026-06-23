use tx_planner::{PlanError, SpendSessionError};
use types::AspMembershipSync;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("not implemented")]
    NotImplemented,

    #[error("pool not initialized")]
    NotInitialized,

    #[error("chain state not synced; call sync() first")]
    NotSynced,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error(transparent)]
    Plan(#[from] PlanError),

    #[error(transparent)]
    SpendSession(#[from] SpendSessionError),

    #[error("ASP membership sync required: {0:?}")]
    MembershipSync(AspMembershipSync),

    #[error("{0}")]
    Other(String),
}

impl PoolError {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
