use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use stellar_private_payments::{
    ProverArtifacts,
    disclosure::{
        RegisteredCircuit, SELECTIVE_DISCLOSURE_1, SELECTIVE_DISCLOSURE_2, SELECTIVE_DISCLOSURE_3,
        SELECTIVE_DISCLOSURE_4,
    },
    types::PolicyFlags,
};

use crate::config::default_data_dir;

const DISCLOSURE_CIRCUITS: [&RegisteredCircuit; 4] = [
    &SELECTIVE_DISCLOSURE_1,
    &SELECTIVE_DISCLOSURE_2,
    &SELECTIVE_DISCLOSURE_3,
    &SELECTIVE_DISCLOSURE_4,
];

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

pub fn load_disclosure_artifacts(
    circuits_dir: Option<&Path>,
) -> Result<Vec<(&'static RegisteredCircuit, ProverArtifacts)>> {
    DISCLOSURE_CIRCUITS
        .into_iter()
        .map(|circuit| {
            load_disclosure_artifacts_for_circuit(circuits_dir, circuit)
                .map(|bundles| (circuit, bundles))
        })
        .collect()
}

pub fn load_disclosure_artifacts_for_circuit(
    circuits_dir: Option<&Path>,
    circuit: &'static RegisteredCircuit,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_circuits_dir);
    let r1cs = circuits.join(circuit.artifacts.r1cs);

    Ok(ProverArtifacts {
        proving_key: read_artifact_file(&circuits, circuit.artifacts.proving_key)?,
        circuit_graph: read_artifact_file(&circuits, circuit.artifacts.graph)?,
        circuit_r1cs: std::fs::read(&r1cs).with_context(|| format!("read {}", r1cs.display()))?,
    })
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
    read_artifact_file(circuits, &format!("{stem}_proving_key.bin"))
}

/// Read a named circuit artifact, preferring the runtime circuits directory and
/// falling back to the copy committed under
/// `deployments/testnet/circuit_keys/`.
///
/// Proving keys and witness graphs both ship committed, so neither requires a
/// circuit build; only the r1cs is a build output.
fn read_artifact_file(circuits: &Path, file_name: &str) -> Result<Vec<u8>> {
    let runtime = circuits.join(file_name);
    if runtime.exists() {
        return std::fs::read(&runtime).with_context(|| format!("read {}", runtime.display()));
    }

    let committed = committed_circuit_keys_dir().join(file_name);
    std::fs::read(&committed).with_context(|| {
        format!(
            "read {file_name} from {} or {} (run the installer or build circuits)",
            runtime.display(),
            committed.display(),
        )
    })
}

/// Read a circom-witness-rs graph for the given circuit stem.
fn read_circuit_graph(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    read_artifact_file(circuits, &format!("{stem}.graph.bin"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_all_registered_disclosure_artifacts() -> Result<()> {
        let circuits =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/circuits-artifacts");
        let artifacts = load_disclosure_artifacts(Some(&circuits))?;

        assert_eq!(artifacts.len(), 4);
        for (index, (circuit, bundle)) in artifacts.iter().enumerate() {
            assert_eq!(usize::try_from(circuit.n_notes)?, index + 1);
            assert!(!bundle.proving_key.is_empty());
            assert!(!bundle.circuit_graph.is_empty());
            assert!(!bundle.circuit_r1cs.is_empty());
        }
        Ok(())
    }
}
