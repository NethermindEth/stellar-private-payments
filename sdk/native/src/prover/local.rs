use std::{cell::RefCell, collections::HashMap};

use crate::{
    types::{DisclosureReceipt, PolicyFlags},
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
/// Transact engines are keyed by [`PolicyFlags`]. Disclosure engines are keyed
/// by their registered circuit name.
pub struct LocalProver {
    transact: RefCell<HashMap<PolicyFlags, ProverEngine>>,
    disclosure: RefCell<HashMap<&'static str, ProverEngine>>,
}

impl LocalProver {
    pub fn from_artifacts(artifacts: &[(PolicyFlags, ProverArtifacts)]) -> Result<Self, Error> {
        if artifacts.is_empty() {
            return Err(Error::Other(
                "at least one transact circuit is required".into(),
            ));
        }
        Self::from_all_artifacts(artifacts, &[])
    }

    pub fn from_disclosure_artifacts(
        artifacts: &[(&'static RegisteredCircuit, ProverArtifacts)],
    ) -> Result<Self, Error> {
        if artifacts.is_empty() {
            return Err(Error::Other(
                "at least one disclosure circuit is required".into(),
            ));
        }
        Self::from_all_artifacts(&[], artifacts)
    }

    pub fn from_all_artifacts(
        transact_artifacts: &[(PolicyFlags, ProverArtifacts)],
        disclosure_artifacts: &[(&'static RegisteredCircuit, ProverArtifacts)],
    ) -> Result<Self, Error> {
        if transact_artifacts.is_empty() && disclosure_artifacts.is_empty() {
            return Err(Error::Other("at least one circuit is required".into()));
        }

        let mut transact = HashMap::with_capacity(transact_artifacts.len());
        for (flags, bundle) in transact_artifacts {
            let engine = ProverEngine::new(
                &bundle.proving_key,
                &bundle.circuit_graph,
                &bundle.circuit_r1cs,
            )
            .map_err(|e| Error::Other(format!("init prover for {flags:?}: {e:#}")))?;
            if transact.insert(*flags, engine).is_some() {
                return Err(Error::Other(format!(
                    "duplicate transact circuit for policy flags {flags:?}"
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
            .map_err(|e| Error::Other(format!("init prover for {}: {e:#}", circuit.name)))?;
            if disclosure.insert(circuit.name, engine).is_some() {
                return Err(Error::Other(format!(
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
        let flags = params.policy_flags;
        self.transact
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
        params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error> {
        let note_count = u32::try_from(params.notes.len())
            .map_err(|_| Error::Other("disclosure note count out of range".into()))?;
        let circuit = find_circuit_by_notes(note_count).ok_or_else(|| {
            Error::Other(format!(
                "no disclosure circuit registered for {note_count} note(s)"
            ))
        })?;
        let mut disclosure = self.disclosure.borrow_mut();
        let engine = disclosure.get_mut(circuit.name).ok_or_else(|| {
            Error::Other(format!(
                "no disclosure prover configured for {}",
                circuit.name
            ))
        })?;
        engine
            .prove_disclosure(params, circuit)
            .map_err(|e| Error::Other(format!("prove disclosure: {e:#}")))
    }

    async fn verify_disclosure_proof(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool, Error> {
        let circuit = validate_registered_receipt(receipt, expected_vk_hash)
            .map_err(|e| Error::Other(format!("validate disclosure receipt: {e:#}")))?;
        let disclosure = self.disclosure.borrow();
        let engine = disclosure.get(circuit.name).ok_or_else(|| {
            Error::Other(format!(
                "no disclosure verifier configured for {}",
                circuit.name
            ))
        })?;
        engine
            .verify_disclosure(receipt, expected_vk_hash)
            .map_err(|e| Error::Other(format!("verify disclosure proof: {e:#}")))
    }
}
