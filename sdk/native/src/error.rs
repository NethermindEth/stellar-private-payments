use crate::{
    planner::{PlanError, SpendSessionError},
    types::AspMembershipSync,
};

use crate::types::TransactionResult;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error(transparent)]
    Plan(#[from] PlanError),

    #[error(transparent)]
    SpendSession(#[from] SpendSessionError),

    #[error("ASP membership sync required: {0:?}")]
    MembershipSync(AspMembershipSync),

    #[error(transparent)]
    PlanExecution(#[from] PlanExecutionError),

    /// The user rejected the wallet signing request (SEP-0043 error code -4).
    #[error("wallet request rejected by user: {0}")]
    UserRejected(String),

    /// The wallet signed with a different account than the one requested —
    /// the signature is not attributable to the identity the request was
    /// built for, and must not be accepted as if it were.
    #[error("wallet signed with {actual}, but {requested} was requested")]
    SignerAddressMismatch { requested: String, actual: String },

    /// A session was requested in which the signing account is not the note
    /// owner.
    ///
    /// Nothing downstream honours the two differing — the envelope source, the
    /// pool contract's `sender` and the auth-entry signer are all built from
    /// the owner — so a divergent pair is refused rather than silently
    /// collapsed. Whether divergence should be supported is an open question.
    #[error(
        "signing account {signer} is not the note owner {owner}; a session where they differ is not supported"
    )]
    SignerIsNotNoteOwner { owner: String, signer: String },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn other(msg: impl Into<String>) -> Self {
        Self::Other(msg.into())
    }
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
