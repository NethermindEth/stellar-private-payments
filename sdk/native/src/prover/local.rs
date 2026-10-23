use std::{collections::HashMap, fmt::Display, sync::Mutex};

use anyhow::Context;

use crate::{
    types::{CircuitStem, DisclosureReceipt, KEY_OWNERSHIP_CIRCUIT},
    zk::flows::{KeyOwnershipParams, TransactParams},
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

/// In-process Groth16 prover for pool transact, selective-disclosure and
/// key ownership circuits.
///
/// Transact engines are keyed by [`CircuitStem`]. Disclosure engines are keyed
/// by their registered circuit name.
pub struct LocalProver {
    transact: Mutex<HashMap<CircuitStem, ProverEngine>>,
    disclosure: Mutex<HashMap<&'static str, ProverEngine>>,
    key_ownership: Mutex<Option<ProverEngine>>,
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
            let engine = init_engine(bundle, stem)?;
            if transact.insert(*stem, engine).is_some() {
                return Err(Error::Other(anyhow::anyhow!(
                    "duplicate transact circuit for {stem}"
                )));
            }
        }

        let mut disclosure = HashMap::with_capacity(disclosure_artifacts.len());
        for (circuit, bundle) in disclosure_artifacts {
            let engine = init_engine(bundle, circuit.name)?;
            if disclosure.insert(circuit.name, engine).is_some() {
                return Err(Error::Other(anyhow::anyhow!(
                    "duplicate disclosure circuit for {}",
                    circuit.name
                )));
            }
        }

        Ok(Self {
            transact: Mutex::new(transact),
            disclosure: Mutex::new(disclosure),
            key_ownership: Mutex::new(None),
        })
    }

    /// A prover for the `keyOwnership` circuit only.
    pub fn from_key_ownership_artifacts(artifacts: &ProverArtifacts) -> Result<Self, Error> {
        Ok(Self {
            transact: Mutex::new(HashMap::new()),
            disclosure: Mutex::new(HashMap::new()),
            key_ownership: Mutex::new(Some(init_engine(artifacts, KEY_OWNERSHIP_CIRCUIT)?)),
        })
    }

    /// Adds the `keyOwnership` circuit.
    pub fn with_key_ownership_artifacts(self, artifacts: &ProverArtifacts) -> Result<Self, Error> {
        Ok(Self {
            key_ownership: Mutex::new(Some(init_engine(artifacts, KEY_OWNERSHIP_CIRCUIT)?)),
            ..self
        })
    }

    pub fn prove(&self, params: TransactParams) -> Result<PreparedProverTx, Error> {
        let stem = CircuitStem::transact(params.policy_flags, params.gvk_mode);
        self.transact
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&stem)
            .ok_or_else(|| {
                Error::Other(anyhow::anyhow!("no transact prover configured for {stem}"))
            })?
            .prove_transact(params)
            .context("prove")
            .map_err(Into::into)
    }
}

fn init_engine(artifacts: &ProverArtifacts, circuit: impl Display) -> Result<ProverEngine, Error> {
    Ok(ProverEngine::new(
        &artifacts.proving_key,
        &artifacts.circuit_graph,
        &artifacts.circuit_r1cs,
    )
    .with_context(|| format!("init prover for {circuit}"))?)
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
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
        let disclosure = self.disclosure.lock().unwrap_or_else(|e| e.into_inner());
        let engine = disclosure.get(circuit.name).ok_or_else(|| {
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
        let disclosure = self.disclosure.lock().unwrap_or_else(|e| e.into_inner());
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

    async fn prove_key_ownership(&self, params: KeyOwnershipParams) -> Result<Vec<u8>, Error> {
        self.key_ownership
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or_else(|| {
                Error::Other(anyhow::anyhow!(
                    "no prover configured for {KEY_OWNERSHIP_CIRCUIT}"
                ))
            })?
            .prove_key_ownership(params)
            .context("prove key ownership")
            .map_err(Into::into)
    }
}
