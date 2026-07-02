use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::default_data_dir;
use stellar_private_payments_sdk::ProverArtifacts;

pub fn load_prover_artifacts(circuits_dir: Option<&Path>) -> Result<ProverArtifacts> {
    let circuits = circuits_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_circuits_dir);

    Ok(ProverArtifacts {
        proving_key: read_proving_key(&circuits)?,
        circuit_wasm: std::fs::read(circuits.join("policy_tx_2_2.wasm"))
            .with_context(|| format!("read {}", circuits.join("policy_tx_2_2.wasm").display()))?,
        circuit_r1cs: std::fs::read(circuits.join("policy_tx_2_2.r1cs"))
            .with_context(|| format!("read {}", circuits.join("policy_tx_2_2.r1cs").display()))?,
    })
}

/// Read the `policy_tx_2_2` proving key.
///
/// Installed builds ship the key alongside the r1cs/wasm in the data-dir `dist`
/// (`<circuits_dir>/policy_tx_2_2_proving_key.bin`). When it is absent — e.g.
/// an in-repo `cargo run` before the dist is provisioned — fall back to the
/// canonical key committed under `deployments/testnet/circuit_keys/`.
fn read_proving_key(circuits: &Path) -> Result<Vec<u8>> {
    let runtime = circuits.join("policy_tx_2_2_proving_key.bin");
    if runtime.exists() {
        return std::fs::read(&runtime).with_context(|| format!("read {}", runtime.display()));
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let committed =
        repo_root.join("deployments/testnet/circuit_keys/policy_tx_2_2_proving_key.bin");
    std::fs::read(&committed).with_context(|| {
        format!(
            "read policy_tx_2_2 proving key from {} or {} (run the installer / build the dist)",
            runtime.display(),
            committed.display(),
        )
    })
}

fn default_circuits_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from("target/circuits-artifacts/release")
    } else {
        default_data_dir().join("dist/circuits")
    }
}
