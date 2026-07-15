use std::{cell::RefCell, collections::HashMap};

use prover::flows::TransactParams;
use types::{DisclosureReceipt, PolicyFlags};

use crate::{
    disclosure::DisclosureProveParams,
    error::PoolError,
    prover::{Prover, ProverEngine},
    transact::PreparedProverTx,
    types::ProverArtifacts,
};

/// In-process Groth16 prover for pool transact circuits.
///
/// Holds one [`ProverEngine`] per [`PolicyFlags`]. Witness/proof generation
/// follows `params.policy_flags` (on-chain pool policy).
pub struct LocalProver(RefCell<HashMap<PolicyFlags, ProverEngine>>);

impl LocalProver {
    pub fn from_artifacts(artifacts: &[(PolicyFlags, ProverArtifacts)]) -> Result<Self, PoolError> {
        let mut engines = HashMap::with_capacity(artifacts.len());
        for (flags, bundle) in artifacts {
            let engine = ProverEngine::new(
                &bundle.proving_key,
                &bundle.circuit_wasm,
                &bundle.circuit_r1cs,
            )
            .map_err(|e| PoolError::Other(format!("init prover for {flags:?}: {e:#}")))?;
            engines.insert(*flags, engine);
        }
        if engines.is_empty() {
            return Err(PoolError::Other(
                "at least one transact circuit is required".into(),
            ));
        }
        Ok(Self(RefCell::new(engines)))
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        let flags = params.policy_flags;
        self.0
            .borrow_mut()
            .get_mut(&flags)
            .ok_or_else(|| {
                PoolError::Other(format!(
                    "no transact prover configured for policy flags {flags:?}"
                ))
            })?
            .prove_transact(params)
            .map_err(|e| PoolError::Other(format!("prove: {e:#}")))
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for LocalProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, PoolError> {
        self.prove(params)
    }

    async fn prove_disclosure(
        &self,
        _params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, PoolError> {
        Err(PoolError::Other(
            "disclosure proving is not configured for this prover".into(),
        ))
    }

    async fn verify_disclosure_proof(
        &self,
        _receipt: &DisclosureReceipt,
        _expected_vk_hash: &str,
    ) -> Result<bool, PoolError> {
        Err(PoolError::Other(
            "disclosure verification is not configured for this prover".into(),
        ))
    }
}
