use std::{cell::RefCell, collections::HashMap};

use anyhow::Context;

use crate::{
    types::{CircuitStem, DisclosureReceipt},
    zk::flows::TransactParams,
};

use super::{Prover, ProverEngine};
use crate::{
    disclosure::{
        DisclosureProveParams, RegisteredCircuit, find_circuit_by_notes,
        validate_registered_receipt,
    },
    error::Error,
    transact::PreparedProverTx,
    types::ProverArtifacts,
};

/// In-process Groth16 prover for pool transact and selective-disclosure
/// circuits.
///
/// Transact engines are keyed by [`CircuitStem`]. Disclosure engines are keyed
/// by their registered circuit name.
pub struct LocalProver {
    transact: RefCell<HashMap<CircuitStem, ProverEngine>>,
    disclosure: RefCell<HashMap<&'static str, ProverEngine>>,
}

impl LocalProver {
    pub fn from_artifacts(artifacts: &[(CircuitStem, ProverArtifacts)]) -> Result<Self, Error> {
        if artifacts.is_empty() {
            return Err(Error::Other(anyhow::anyhow!(
                "at least one transact circuit is required"
            )));
        }
        Self::from_all_artifacts(artifacts, &[])
    }

    pub fn from_disclosure_artifacts(
        artifacts: &[(&'static RegisteredCircuit, ProverArtifacts)],
    ) -> Result<Self, Error> {
        if artifacts.is_empty() {
            return Err(Error::Other(anyhow::anyhow!(
                "at least one disclosure circuit is required"
            )));
        }
        Self::from_all_artifacts(&[], artifacts)
    }

    pub fn from_all_artifacts(
        transact_artifacts: &[(CircuitStem, ProverArtifacts)],
        disclosure_artifacts: &[(&'static RegisteredCircuit, ProverArtifacts)],
    ) -> Result<Self, Error> {
        if transact_artifacts.is_empty() && disclosure_artifacts.is_empty() {
            return Err(Error::Other(anyhow::anyhow!(
                "at least one circuit is required"
            )));
        }

        let mut transact = HashMap::with_capacity(transact_artifacts.len());
        for (stem, bundle) in transact_artifacts {
            let engine = ProverEngine::new(
                &bundle.proving_key,
                &bundle.circuit_graph,
                &bundle.circuit_r1cs,
            )
            .context(format!("init prover for {stem}"))?;
            if transact.insert(*stem, engine).is_some() {
                return Err(Error::Other(anyhow::anyhow!(
                    "duplicate transact circuit for {stem}"
                )));
            }
        }

        let mut disclosure = HashMap::with_capacity(disclosure_artifacts.len());
        for (circuit, bundle) in disclosure_artifacts {
            let engine = ProverEngine::new(
                &bundle.proving_key,
                &bundle.circuit_graph,
                &bundle.circuit_r1cs,
            )
            .context(format!("init prover for {}", circuit.name))?;
            if disclosure.insert(circuit.name, engine).is_some() {
                return Err(Error::Other(anyhow::anyhow!(
                    "duplicate disclosure circuit for {}",
                    circuit.name
                )));
            }
        }

        Ok(Self {
            transact: RefCell::new(transact),
            disclosure: RefCell::new(disclosure),
        })
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        let stem = CircuitStem::transact(params.policy_flags, params.gvk_mode);
        self.transact
            .borrow_mut()
            .get_mut(&stem)
            .ok_or_else(|| {
                Error::Other(anyhow::anyhow!("no transact prover configured for {stem}"))
            })?
            .prove_transact(params)
            .context("prove")
            .map_err(Into::into)
    }
}

#[async_trait::async_trait(?Send)]
impl Prover for LocalProver {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        self.prove(params)
    }

    async fn prove_disclosure(
        &self,
        params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        let note_count =
            u32::try_from(params.notes.len()).context("disclosure note count out of range")?;
        let circuit = find_circuit_by_notes(note_count).ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "no disclosure circuit registered for {note_count} note(s)"
            ))
        })?;
        let mut disclosure = self.disclosure.borrow_mut();
        let engine = disclosure.get_mut(circuit.name).ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "no disclosure prover configured for {}",
                circuit.name
            ))
        })?;
        engine
            .prove_disclosure(params, circuit)
            .context("prove disclosure")
            .map_err(Into::into)
    }

    async fn verify_disclosure_proof(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        let circuit = validate_registered_receipt(receipt, expected_vk_hash)
            .context("validate disclosure receipt")?;
        let disclosure = self.disclosure.borrow();
        let engine = disclosure.get(circuit.name).ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "no disclosure verifier configured for {}",
                circuit.name
            ))
        })?;
        engine
            .verify_disclosure(receipt, expected_vk_hash)
            .context("verify disclosure proof")
            .map_err(Into::into)
    }
}
