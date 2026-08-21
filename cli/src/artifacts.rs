use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use stellar_private_payments::{ProverArtifacts, types::PolicyFlags};

use crate::config::default_data_dir;

pub fn load_transact_artifacts(
    circuits_dir: Option<&Path>,
) -> Result<Vec<(PolicyFlags, ProverArtifacts)>> {
    PolicyFlags::all_flags()
        .into_iter()
        .map(|flags| {
            load_transact_artifacts_for_policy(circuits_dir, flags)
                .map(|artifacts| (flags, artifacts))
        })
        .collect()
}

pub fn load_transact_artifacts_for_policy(
    circuits_dir: Option<&Path>,
    policy_flags: PolicyFlags,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_circuits_dir);
    let stem = policy_flags.circuit_stem();

    Ok(ProverArtifacts {
        proving_key: read_proving_key(&circuits, &stem)?,
        circuit_graph: read_circuit_graph(&circuits, &stem)?,
        circuit_r1cs: std::fs::read(circuits.join(format!("{stem}.r1cs")))
            .with_context(|| format!("read {}", circuits.join(format!("{stem}.r1cs")).display()))?,
    })
}

/// Read a Groth16 proving key for the given circuit stem.
///
/// Installed builds ship the key alongside the r1cs/graph in the data dir
/// (`<circuits_dir>/{stem}_proving_key.bin`). When it is absent — e.g.
/// an in-repo `cargo run` before the installer has run — fall back to the
/// canonical key committed under `deployments/testnet/circuit_keys/`.
fn read_proving_key(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    let runtime = circuits.join(format!("{stem}_proving_key.bin"));
    if runtime.exists() {
        return std::fs::read(&runtime).with_context(|| format!("read {}", runtime.display()));
    }

    let committed = committed_circuit_keys_dir().join(format!("{stem}_proving_key.bin"));
    std::fs::read(&committed).with_context(|| {
        format!(
            "read {stem} proving key from {} or {} (run the installer or build circuits)",
            runtime.display(),
            committed.display(),
        )
    })
}

/// Read a circom-witness-rs graph for the given circuit stem.
fn read_circuit_graph(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    let runtime = circuits.join(format!("{stem}.graph.bin"));
    if runtime.exists() {
        return std::fs::read(&runtime).with_context(|| format!("read {}", runtime.display()));
    }

    let committed = committed_circuit_keys_dir().join(format!("{stem}.graph.bin"));
    std::fs::read(&committed).with_context(|| {
        format!(
            "read {stem} witness graph from {} or {} (run `make witness-graphs`)",
            runtime.display(),
            committed.display(),
        )
    })
}

fn committed_circuit_keys_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deployments/testnet/circuit_keys")
}

fn default_circuits_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        PathBuf::from("target/circuits-artifacts")
    } else {
        default_data_dir().join("circuits")
    }
}
