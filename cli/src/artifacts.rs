use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use stellar_private_payments_sdk::{
    ProverArtifacts,
    types::{PolicyMode, policy_tx_stem},
};

use crate::config::default_data_dir;

pub fn load_policy_transact_artifacts(
    circuits_dir: Option<&Path>,
) -> Result<Vec<(PolicyMode, ProverArtifacts)>> {
    [
        PolicyMode::Open,
        PolicyMode::Allowlist,
        PolicyMode::Blocklist,
        PolicyMode::Both,
    ]
    .into_iter()
    .map(|mode| load_prover_artifacts(circuits_dir, mode).map(|artifacts| (mode, artifacts)))
    .collect()
}

pub fn load_prover_artifacts(
    circuits_dir: Option<&Path>,
    policy_mode: PolicyMode,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_circuits_dir);
    let stem = policy_tx_stem(policy_mode);

    Ok(ProverArtifacts {
        proving_key: read_proving_key(&circuits, stem)?,
        circuit_wasm: std::fs::read(circuits.join(format!("{stem}.wasm")))
            .with_context(|| format!("read {}", circuits.join(format!("{stem}.wasm")).display()))?,
        circuit_r1cs: std::fs::read(circuits.join(format!("{stem}.r1cs")))
            .with_context(|| format!("read {}", circuits.join(format!("{stem}.r1cs")).display()))?,
    })
}

/// Read a Groth16 proving key for the given circuit stem.
///
/// Installed builds ship the key alongside the r1cs/wasm in the data dir
/// (`<circuits_dir>/{stem}_proving_key.bin`). When it is absent — e.g.
/// an in-repo `cargo run` before the installer has run — fall back to the
/// canonical key committed under `deployments/testnet/circuit_keys/`.
fn read_proving_key(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    let runtime = circuits.join(format!("{stem}_proving_key.bin"));
    if runtime.exists() {
        return std::fs::read(&runtime).with_context(|| format!("read {}", runtime.display()));
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let committed = repo_root.join(format!(
        "deployments/testnet/circuit_keys/{stem}_proving_key.bin"
    ));
    std::fs::read(&committed).with_context(|| {
        format!(
            "read {stem} proving key from {} or {} (run the installer or build circuits)",
            runtime.display(),
            committed.display(),
        )
    })
}

fn default_circuits_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from("target/circuits-artifacts/release")
    } else {
        default_data_dir().join("circuits")
    }
}
