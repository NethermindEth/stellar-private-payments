use crate::{
    chain::IndexerError,
    planner::{PlanError, SpendSessionError},
    types::{AspMembershipSync, Sensitive},
};

use crate::types::TransactionResult;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("RPC error")]
    Rpc(#[from] crate::chain::RpcError),

    #[error(transparent)]
    Plan(#[from] PlanError),

    #[error(transparent)]
    SpendSession(#[from] SpendSessionError),

    #[error("ASP membership sync required: {0:?}")]
    MembershipSync(AspMembershipSync),

    #[error(transparent)]
    PlanExecution(#[from] PlanExecutionError),

    /// The user rejected the wallet signing request (SEP-0043 error code -4)
    #[error("wallet request rejected by user: {0}")]
    UserRejected(String),

    /// The signing account is not the note owner.
    ///
    /// The two transaction paths disagree on which identity drives them:
    /// transact sources the envelope, `sender` and sequence number from the
    /// signer, registration from the owner. Which is right when they differ is
    /// unsettled, so a divergent pair is refused rather than resolved here.
    // Escapes to a UI toast, the telemetry ring buffer and CLI logs.
    #[error(
        "signing account {} is not the note owner {}; a session where they differ is not supported",
        Sensitive(signer),
        Sensitive(owner)
    )]
    SignerIsNotNoteOwner { owner: String, signer: String },

    /// Local storage has no privacy keys for address
    #[error(
        "no privacy keys found in local storage for {}",
        Sensitive(user_address)
    )]
    UserKeysNotFound { user_address: String },

    #[error("event history is unavailable: {0}")]
    RetentionGap(#[from] RetentionGap),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionGap {
    #[error("main RPC is missing event history and no fallback bootnode is configured")]
    SyncGap,

    #[error("configured bootnode failed to fill retention gap: {0}")]
    BootnodeFailed(String),
}

/// Multi-tx plan stopped after one or more steps had already confirmed
/// on-chain.
///
/// `completed` are those successes; `cause` is why the remaining steps did not
/// finish. Recovery is sync + a fresh plan from current notes — the same plan
/// is not resumed.
#[derive(Debug, thiserror::Error)]
#[error("plan failed after {} confirmed transaction(s): {cause}", .completed.len())]
pub struct PlanExecutionError {
    pub completed: Vec<TransactionResult>,
    #[source]
    pub cause: Box<Error>,
}

impl PlanExecutionError {
    /// Attach already-confirmed txs to a mid-plan failure. If `completed` is
    /// empty, returns `cause` unchanged (no wrapper).
    pub fn into_error(mut completed: Vec<TransactionResult>, cause: Error) -> Error {
        match cause {
            Error::PlanExecution(PlanExecutionError {
                completed: mut nested,
                cause,
            }) => {
                completed.append(&mut nested);
                Self::into_error(completed, *cause)
            }
            cause if completed.is_empty() => cause,
            cause => Error::PlanExecution(PlanExecutionError {
                completed,
                cause: Box::new(cause),
            }),
        }
    }

    /// Underlying failure, unwrapping nested [`Error::PlanExecution`] if any.
    pub fn cause(&self) -> &Error {
        match self.cause.as_ref() {
            Error::PlanExecution(inner) => inner.cause(),
            other => other,
        }
    }
}

impl From<IndexerError> for Error {
    fn from(ierr: IndexerError) -> Self {
        match ierr {
            IndexerError::Rpc(e) => e.into(),
            IndexerError::Other(e) => e.into(),
        }
    }
}
