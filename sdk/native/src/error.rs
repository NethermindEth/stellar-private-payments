use crate::{
    chain::IndexerError,
    planner::{PlanError, SpendSessionError},
    types::{AspMembershipSync, ExtAmount, NoteAmount, Sensitive},
};

use crate::types::TransactionResult;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("not implemented")]
    NotImplemented,

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// A request the SDK refuses before it reaches the network.
    #[error("{0}")]
    Refused(String),

    #[error(transparent)]
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
        Sensitive(signer),
        Sensitive(owner)
    )]
    SignerIsNotNoteOwner { owner: String, signer: String },

    /// The account has no ledger entry on-chain yet
    #[error("account {} not found on-chain", crate::types::Sensitive(address))]
    AccountNotFound { address: String },

    /// The public key registry was deployed for another key derivation domain
    /// than this session's config.
    #[error(
        "the public key registry uses key derivation domain {registry:?}, but this deployment's config uses {config:?}"
    )]
    KdfDomainMismatch { registry: String, config: String },

    /// Local storage has no privacy keys for address
    #[error(
        "no privacy keys found in local storage for {}; derive privacy keys first",
        Sensitive(user_address)
    )]
    PrivacyKeysNotFound { user_address: String },

    #[error("disclosure verification failed: {0}")]
    DisclosureVerification(String),

    #[error("event history is unavailable: {0}")]
    RetentionGap(#[from] RetentionGap),

    /// A deposit into a paused pool, refused before proving.
    #[error("deposits into pool {pool} are paused")]
    DepositsPaused { pool: String },

    /// A deposit leaves less than the pool's minimum in notes once the fee is
    /// paid.
    #[error("deposit is below the pool minimum of {minimum} base units after the pool fee")]
    DepositBelowMinimum { minimum: NoteAmount },

    /// A deposit sends more than the pool's maximum, which counts the pool
    /// fee. `largest_deposit` is the most a deposit can put in notes: the
    /// maximum less the fee.
    #[error("deposit sends more than the pool maximum of {maximum} base units, pool fee included")]
    DepositAboveMaximum {
        maximum: ExtAmount,
        largest_deposit: NoteAmount,
    },

    /// A transaction whose inputs and deposit do not pay its outputs,
    /// withdrawal and fee. `gap` is negative when more goes out than comes in.
    // Names no amount: the gap can reveal a note's value.
    #[error(
        "transaction does not balance: {}",
        if .gap < &ExtAmount::ZERO {
            "the private outputs, withdrawal and pool fee exceed the input notes and deposit"
        } else {
            "the input notes and deposit exceed the private outputs, withdrawal and pool fee"
        }
    )]
    NotBalanced { gap: ExtAmount },

    /// A withdrawal paid to a contract of this deployment.
    #[error(
        "cannot withdraw to a contract of this deployment, such as a pool or its token contract, because nobody could move the tokens out again; withdraw to an address outside this deployment"
    )]
    WithdrawalToContract,

    /// The events synced for a contract differ from those it published, as its
    /// event chain shows: an event was altered, added, or reordered. Nothing
    /// read from them can be trusted until the contract's history is reset and
    /// synced again from a source that serves it whole.
    #[error(
        "the {synced} events synced for contract {contract} differ from the {published} it published; reset its history and sync again"
    )]
    EventHistoryMismatch {
        contract: String,
        synced: u64,
        published: u64,
    },

    /// Fewer events are synced for a contract than it published, after
    /// catching up: an event was withheld. Nothing read from them can be
    /// trusted until the contract's history is reset and synced again from a
    /// source that serves it whole.
    #[error(
        "only {synced} of the {published} events contract {contract} published are synced; reset its history and sync again"
    )]
    EventHistoryIncomplete {
        contract: String,
        synced: u64,
        published: u64,
    },

    /// An untyped failure.
    ///
    /// The message holds the whole `anyhow` cause chain, so the variant has no
    /// `source`, which would print every cause twice.
    #[error("{0:#}")]
    Other(anyhow::Error),

    /// An admin call reads entries that archive before its signers can be
    /// expected to send it. Each command extends one of them, paid by
    /// `ACCOUNT`.
    #[error(
        "entries this call reads archive before it expires, so it would fail once sent; extend them, then build the call again"
    )]
    EntriesArchiveSoon { extend_commands: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum RetentionGap {
    #[error("main RPC is missing event history and no fallback bootnode is configured")]
    SyncGap,

    /// The bootnode cannot serve this deployment; retrying cannot help.
    #[error("configured bootnode failed to fill retention gap: {0}")]
    BootnodeFailed(String),

    /// The bootnode cannot answer now; retry later.
    #[error("configured bootnode cannot serve the event history yet: {0}")]
    BootnodeNotReady(String),
}

impl Error {
    /// Returns the error that stopped a plan, past the steps it confirmed, or
    /// this error when it is not a plan failure.
    pub fn root_cause(&self) -> &Error {
        match self {
            Error::PlanExecution(plan) => plan.cause(),
            other => other,
        }
    }

    /// Returns the planner's error, bare or through a spend session. Call it on
    /// [`Self::root_cause`] to read past the steps a plan confirmed.
    pub fn plan_error(&self) -> Option<&PlanError> {
        match self {
            Error::Plan(error) | Error::SpendSession(SpendSessionError::Plan(error)) => Some(error),
            _ => None,
        }
    }

    /// Returns the most the notes can send, when planning a spend failed for
    /// want of funds. Call it on [`Self::root_cause`] to read past the steps a
    /// plan confirmed.
    pub fn max_spend(&self) -> Option<NoteAmount> {
        match self.plan_error()? {
            PlanError::NoCombination { max_spend } => Some(*max_spend),
            _ => None,
        }
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

impl From<IndexerError> for Error {
    fn from(ierr: IndexerError) -> Self {
        match ierr {
            IndexerError::Rpc(e) => e.into(),
            IndexerError::Other(e) => e.into(),
        }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untyped_error_prints_its_causes() {
        let error = Error::Other(
            anyhow::anyhow!("HostError: Error(Contract, #18)").context("simulate transaction"),
        );
        assert_eq!(
            error.to_string(),
            "simulate transaction: HostError: Error(Contract, #18)"
        );
    }

    #[test]
    fn a_wrapped_untyped_error_prints_each_cause_once() {
        let inner = Error::Other(anyhow::anyhow!("B").context("A"));
        let error = Error::Other(anyhow::Error::from(inner).context("sync"));
        assert_eq!(error.to_string(), "sync: A: B");
    }
}
