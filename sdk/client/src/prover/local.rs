use std::cell::RefCell;

use prover::flows::TransactParams;
use types::DisclosureReceipt;

use crate::{
    disclosure::DisclosureProveParams,
    error::Error,
    prover::{Prover, ProverEngine},
    transact::PreparedProverTx,
    types::ProverArtifacts,
};

/// [`Prover`] backed by in-process [`ProverEngine`].
pub struct LocalProver(RefCell<ProverEngine>);

impl LocalProver {
    pub fn from_artifacts(artifacts: &ProverArtifacts) -> Result<Self, Error> {
        ProverEngine::new(
            &artifacts.proving_key,
            &artifacts.circuit_wasm,
            &artifacts.circuit_r1cs,
        )
        .map(|engine| Self(RefCell::new(engine)))
        .map_err(|e| Error::Other(format!("init prover: {e:#}")))
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        self.0
            .borrow_mut()
            .prove_transact(params)
            .map_err(|e| Error::Other(format!("prove: {e:#}")))
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for LocalProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        self.prove(params)
    }

    async fn prove_disclosure(
        &self,
        _params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        Err(Error::Other(
            "disclosure proving is not configured for this prover".into(),
        ))
    }

    async fn verify_disclosure_proof(
        &self,
        _receipt: &DisclosureReceipt,
        _expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        Err(Error::Other(
            "disclosure verification is not configured for this prover".into(),
        ))
    }
}
