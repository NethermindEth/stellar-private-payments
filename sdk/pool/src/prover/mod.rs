//! Groth16 transact proving — local in-process or pluggable async backend.

mod local;

pub use local::{LocalTransactionProver, ProverEngine};

use prover::flows::TransactParams;

use crate::{error::PoolError, transact::PreparedProverTx, types::ProverArtifacts};

/// Proves a single pool `transact` step.
///
/// Native sync clients use [`LocalTransactionProver`]; browser apps may supply
/// a worker-backed implementation over channels.
#[async_trait::async_trait(?Send)]
pub trait TransactionProver {
    async fn prove_transact(
        &mut self,
        params: TransactParams,
    ) -> Result<PreparedProverTx, PoolError>;
}

/// Build a local in-process prover from circuit artifacts.
pub fn local_transaction_prover(
    artifacts: &ProverArtifacts,
) -> Result<LocalTransactionProver, PoolError> {
    LocalTransactionProver::from_artifacts(artifacts)
}
