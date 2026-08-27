//! Groth16 transact proving — local in-process or pluggable async backend.

mod local;
mod noop;

pub use local::LocalProver;
pub(crate) use noop::NoopProver;

use crate::{
    chain::hash_ext_data_offchain,
    zk::{
        flows::{
            DisclosureNote, SelectiveDisclosureParams, TransactArtifacts, TransactParams,
            selective_disclosure, transact,
        },
        prover::Prover as Groth16Prover,
        witness::WitnessCalculator,
    },
};
use anyhow::{Context, Result};

use crate::{
    disclosure::{DisclosureProveParams, RegisteredCircuit},
    error::Error,
    transact::{PreparedProverTx, PreparedTxPublic},
    types::{DISCLOSURE_RECEIPT_VERSION, DisclosurePublicInputs, DisclosureReceipt},
};

/// In-process Groth16 prover for transact circuits.
pub struct ProverEngine {
    witness: WitnessCalculator,
    prover: Groth16Prover,
}

impl ProverEngine {
    pub fn new(proving_key: &[u8], circuit_graph: &[u8], r1cs: &[u8]) -> Result<Self> {
        let witness = WitnessCalculator::from_graph(circuit_graph)
            .context("failed to init witness calculator")?;
        let prover = Groth16Prover::new(proving_key, r1cs).context("failed to init prover")?;
        Ok(Self { witness, prover })
    }

    /// Create a new ProverEngine from an arkworks-*uncompressed* proving key.
    ///
    /// Mirrors [`ProverEngine::new`] but reads the encoding produced by
    /// [`ProverEngine::get_uncompressed_proving_key`], skipping point
    /// decompression on the (larger) proving key. This is the fast path for a
    /// warm circuit cache.
    pub fn new_from_uncompressed_pk(
        proving_key: &[u8],
        circuit_graph: &[u8],
        r1cs: &[u8],
    ) -> Result<Self> {
        let witness = WitnessCalculator::from_graph(circuit_graph)
            .context("failed to init witness calculator")?;
        let prover = Groth16Prover::new_from_uncompressed_pk(proving_key, r1cs)
            .context("failed to init prover from uncompressed proving key")?;
        Ok(Self { witness, prover })
    }

    /// Serialize the proving key in arkworks-*uncompressed* form, for caching.
    ///
    /// The output is the exact byte layout expected by
    /// [`ProverEngine::new_from_uncompressed_pk`].
    pub fn get_uncompressed_proving_key(&self) -> Result<Vec<u8>> {
        self.prover.get_uncompressed_proving_key()
    }

    pub fn prove_transact(&mut self, params: TransactParams) -> Result<PreparedProverTx> {
        let artifacts = transact(params, hash_ext_data_offchain)?;
        self.prove(artifacts)
    }

    pub(crate) fn prove_disclosure(
        &mut self,
        params: DisclosureProveParams,
        circuit: &'static RegisteredCircuit,
    ) -> Result<DisclosureReceipt> {
        let note_count = u32::try_from(params.notes.len())
            .context("disclosure note count does not fit in u32")?;
        if note_count != circuit.n_notes {
            anyhow::bail!(
                "disclosure circuit {} expects {} note(s), got {note_count}",
                circuit.name,
                circuit.n_notes
            );
        }

        let context = params.context;
        let ext_context_hash = crate::zk::disclosure::derive_ext_context_hash(&context)?;
        let roots = params.notes.iter().map(|input| input.root).collect();
        let note_commitments = params
            .notes
            .iter()
            .map(|input| input.note_commitment)
            .collect();
        let notes = params
            .notes
            .into_iter()
            .map(|input| DisclosureNote {
                root: input.root,
                note_commitment: input.note_commitment,
                note_amount: input.note_amount,
                note_private_key: input.note_private_key,
                note_blinding: input.note_blinding,
                merkle_path_indices: input.merkle_path_indices,
                merkle_path_elements: input.merkle_path_elements,
            })
            .collect();

        let artifacts = selective_disclosure(SelectiveDisclosureParams {
            notes,
            ext_context_hash,
        })?;
        let circuit_inputs_json = serde_json::to_string(&artifacts.circuit_inputs)?;
        let witness_bytes = self
            .witness
            .compute_witness(&circuit_inputs_json)
            .context("disclosure witness calculation failed")?;
        let proved =
            crate::zk::disclosure::prove_receipt_proof_with_prover(&self.prover, &witness_bytes)?;
        let vk_hash = crate::zk::disclosure::vk_hash_hex(&self.prover.get_verifying_key()?);

        Ok(DisclosureReceipt {
            version: DISCLOSURE_RECEIPT_VERSION,
            circuit: circuit.receipt_metadata(&vk_hash),
            context,
            public_inputs: DisclosurePublicInputs {
                roots,
                note_commitments,
                ext_context_hash,
                nullifiers: artifacts.nullifiers,
                amounts: artifacts.amounts,
            },
            proof_compressed_hex: format!("0x{}", hex::encode(proved.proof_compressed)),
            issued_at: crate::zk::disclosure::current_issued_at()?,
        })
    }

    pub(crate) fn verify_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool> {
        let vk_bytes = self.prover.get_verifying_key()?;
        crate::zk::disclosure::verify_receipt_proof(receipt, &vk_bytes, expected_vk_hash)
    }

    fn prove(&mut self, artifacts: TransactArtifacts) -> Result<PreparedProverTx> {
        let circuit_inputs_json = serde_json::to_string(&artifacts.circuit_inputs)?;
        let ext_data = artifacts.ext_data.clone();

        let witness_bytes = self
            .witness
            .compute_witness(&circuit_inputs_json)
            .context("witness calculation failed")?;

        let proof_compressed = self.prover.prove_bytes(&witness_bytes)?;
        let public_inputs = self.prover.extract_public_inputs(&witness_bytes)?;
        if !self.prover.verify(&proof_compressed, &public_inputs)? {
            anyhow::bail!("proof verification failed");
        }

        let proof_uncompressed = self.prover.proof_bytes_to_uncompressed(&proof_compressed)?;
        if proof_uncompressed.len() != 256 {
            anyhow::bail!(
                "unexpected uncompressed proof length: {}",
                proof_uncompressed.len()
            );
        }

        let p = artifacts.prepared;
        let prepared = PreparedTxPublic {
            pool_root: p.pool_root,
            input_nullifiers: p.input_nullifiers,
            output_commitments: p.output_commitments,
            public_amount: p.public_amount_field,
            ext_data_hash_be: p.ext_data_hash_be,
            asp_membership_root: p.asp_membership_root,
            asp_non_membership_root: p.asp_non_membership_root,
        };

        Ok(PreparedProverTx {
            proof_uncompressed,
            ext_data,
            prepared,
            soroban_tx: Default::default(),
        })
    }
}

/// Proves a single pool `transact` step.
///
/// Native sync clients use [`LocalProver`]; browser apps may supply a
/// worker-backed implementation over channels.
#[async_trait::async_trait(?Send)]
pub trait Prover {
    async fn prove_transact(&self, params: TransactParams) -> Result<PreparedProverTx, Error>;

    async fn prove_disclosure(
        &self,
        params: DisclosureProveParams,
    ) -> Result<DisclosureReceipt, Error>;

    async fn verify_disclosure_proof(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<bool, Error>;
}
