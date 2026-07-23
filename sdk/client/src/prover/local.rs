use std::{cell::RefCell, collections::HashMap};

use prover::flows::TransactParams;
use types::{DisclosureReceipt, PolicyFlags};

use crate::{
    disclosure::DisclosureProveParams,
    error::Error,
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
    pub fn from_artifacts(artifacts: &[(PolicyFlags, ProverArtifacts)]) -> Result<Self, Error> {
        let mut engines = HashMap::with_capacity(artifacts.len());
        for (flags, bundle) in artifacts {
            let engine = ProverEngine::new(
                &bundle.proving_key,
                &bundle.circuit_wasm,
                &bundle.circuit_r1cs,
            )
            .map_err(|e| Error::Other(format!("init prover for {flags:?}: {e:#}")))?;
            engines.insert(*flags, engine);
        }
        if engines.is_empty() {
            return Err(Error::Other(
                "at least one transact circuit is required".into(),
            ));
        }
        Ok(Self(RefCell::new(engines)))
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        let flags = params.policy_flags;
        self.0
            .borrow_mut()
            .get_mut(&flags)
            .ok_or_else(|| {
                Error::Other(format!(
                    "no transact prover configured for policy flags {flags:?}"
                ))
            })?
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
