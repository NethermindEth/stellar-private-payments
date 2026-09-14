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

    /// An operation needs the note owner's own signature, and the session
    /// signs with a different account.
    ///
    /// A session may hold a divergent pair: the payer sources the envelope,
    /// `sender` and sequence number, and spending needs nothing else. Two
    /// operations do need the owner itself — key derivation, whose signature
    /// *is* the note secret, and registration, whose simulated auth entry is
    /// the owner's. Those raise this; the session as a whole does not.
    // Escapes to a UI toast, the telemetry ring buffer and CLI logs.
    #[error(
        "signing account {} cannot sign for the note owner {}; this step needs the owner's own signature",
        crate::types::Sensitive(signer),
        crate::types::Sensitive(owner)
    )]
    SignerIsNotNoteOwner { owner: String, signer: String },

    /// A withdrawal's payout cannot reach the recipient it names.
    ///
    /// The pool pays the recipient inside `transact`, so an address that cannot
    /// hold the asset traps there: for the native asset because the recipient
    /// is not an account and the payout is below what creating one costs,
    /// for a classic asset because it holds no trustline. Simulation runs
    /// immediately before signing and catches it, but reports it as an
    /// unattributed host error; this names the recipient instead.
    /// `simulation` carries the raw diagnostics and is deliberately left
    /// out of the message.
    // Escapes to a UI toast, the telemetry ring buffer and CLI logs.
    #[error(
        "the withdrawal cannot pay {}: the recipient must already be able to hold this asset — an account that exists and, for a classic asset, a trustline for it",
        crate::types::Sensitive(recipient)
    )]
    RecipientCannotReceive {
        recipient: String,
        simulation: String,
    },

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
