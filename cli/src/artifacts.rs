use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::default_data_dir;
use stellar_private_payments_sdk::ProverArtifacts;

pub fn load_prover_artifacts(circuits_dir: Option<&Path>) -> Result<ProverArtifacts> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let circuits = circuits_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_circuits_dir);

    Ok(ProverArtifacts {
        proving_key: std::fs::read(
            repo_root.join("deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin"),
        )
        .context("read policy_tx_2_2 proving key (build circuits / check deployments/testnet/circuit_keys)")?,
        circuit_wasm: std::fs::read(circuits.join("policy_tx_2_2.wasm"))
            .with_context(|| format!("read {}", circuits.join("policy_tx_2_2.wasm").display()))?,
        circuit_r1cs: std::fs::read(circuits.join("policy_tx_2_2.r1cs"))
            .with_context(|| format!("read {}", circuits.join("policy_tx_2_2.r1cs").display()))?,
    })
}

fn default_circuits_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from("target/circuits-artifacts/release")
    } else {
        default_data_dir().join("circuits-artifacts/release")
    }
}
