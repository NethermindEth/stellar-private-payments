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

    /// The account that would pay for a transaction is not on the network.
    ///
    /// Building an envelope reads the paying account's sequence number, so an
    /// account that was never funded fails there, as whatever the RPC returned
    /// for a missing ledger entry. Raised before that read so the account that
    /// needs funding is named.
    // Escapes to a UI toast, the telemetry ring buffer and CLI logs.
    #[error(
        "paying account {} is not on the network; fund it before it can pay for this transaction",
        crate::types::Sensitive(payer)
    )]
    PayingAccountNotFound { payer: String },

    /// The signed transaction still carries an authorization nobody filled.
    ///
    /// Simulation returns one auth entry per address the call requires, and a
    /// signer fills only the entries for accounts whose keys it holds. A
    /// delegated registration needs the owner's, which a signer holding the
    /// payer's key alone cannot produce. Raised instead of submitting a
    /// transaction the contract would refuse.
    // Escapes to a UI toast, the telemetry ring buffer and CLI logs.
    #[error(
        "this transaction needs {}'s authorization and the signer did not produce it; it must be collected before submission",
        crate::types::Sensitive(address)
    )]
    MissingAuthorization { address: String },

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
