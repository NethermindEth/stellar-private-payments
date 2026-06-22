use tx_planner::PlanError;

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("not implemented")]
    NotImplemented,

    #[error("pool not initialized")]
    NotInitialized,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error(transparent)]
    Plan(#[from] PlanError),

    #[error("{0}")]
    Other(String),
}

impl PoolError {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
}
