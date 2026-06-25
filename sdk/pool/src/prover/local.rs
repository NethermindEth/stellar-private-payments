use std::cell::RefCell;

use prover::flows::TransactParams;

use crate::{
    error::PoolError,
    prover::{Prover, ProverEngine},
    transact::PreparedProverTx,
    types::ProverArtifacts,
};

/// [`Prover`] backed by in-process [`ProverEngine`].
pub struct LocalProver(RefCell<ProverEngine>);

impl LocalProver {
    pub fn from_artifacts(artifacts: &ProverArtifacts) -> Result<Self, PoolError> {
        ProverEngine::new(
            &artifacts.proving_key,
            &artifacts.circuit_wasm,
            &artifacts.circuit_r1cs,
        )
        .map(|engine| Self(RefCell::new(engine)))
        .map_err(|e| PoolError::Other(format!("init prover: {e:#}")))
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        self.0
            .borrow_mut()
            .prove_transact(params)
            .map_err(|e| PoolError::Other(format!("prove: {e:#}")))
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for LocalProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        self.prove(params)
    }
}
