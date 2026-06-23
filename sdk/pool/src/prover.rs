use anyhow::{Context, Result};
use prover::{
    flows::{TransactArtifacts, TransactParams, transact},
    prover::Prover,
};
use stellar::hash_ext_data_offchain;
use witness::WitnessCalculator;

use crate::transact::{PreparedProverTx, PreparedTxPublic};

pub struct ProverEngine {
    witness: WitnessCalculator,
    prover: Prover,
}

impl ProverEngine {
    pub fn new(proving_key: &[u8], circuit_wasm: &[u8], r1cs: &[u8]) -> Result<Self> {
        let witness = WitnessCalculator::new(circuit_wasm, r1cs)
            .context("failed to init witness calculator")?;
        let prover = Prover::new(proving_key, r1cs).context("failed to init prover")?;
        Ok(Self { witness, prover })
    }

    pub fn prove_transact(&mut self, params: TransactParams) -> Result<PreparedProverTx> {
        let artifacts = transact(params, hash_ext_data_offchain)?;
        self.prove(artifacts)
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
