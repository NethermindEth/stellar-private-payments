use std::path::Path;

use anyhow::{Context, Result};
use stellar_private_payments::{
    disclosure::{
        RegisteredCircuit, SELECTIVE_DISCLOSURE_1, SELECTIVE_DISCLOSURE_2, SELECTIVE_DISCLOSURE_3,
        SELECTIVE_DISCLOSURE_4,
    },
    types::{CircuitStem, ProverArtifacts},
};

use stellar_private_payments::CircuitLockfile;

const DISCLOSURE_CIRCUITS: [&RegisteredCircuit; 4] = [
    &SELECTIVE_DISCLOSURE_1,
    &SELECTIVE_DISCLOSURE_2,
    &SELECTIVE_DISCLOSURE_3,
    &SELECTIVE_DISCLOSURE_4,
];

pub fn load_transact_artifacts(
    circuits_dir: &Path,
    lock: &CircuitLockfile,
) -> Result<Vec<(CircuitStem, ProverArtifacts)>> {
    CircuitStem::all_transact_stems()
        .into_iter()
        .map(|stem| {
            load_transact_artifacts_for_stem(circuits_dir, lock, stem)
                .map(|artifacts| (stem, artifacts))
        })
        .collect()
}

pub fn load_disclosure_artifacts(
    circuits_dir: &Path,
    lock: &CircuitLockfile,
) -> Result<Vec<(&'static RegisteredCircuit, ProverArtifacts)>> {
    DISCLOSURE_CIRCUITS
        .into_iter()
        .map(|circuit| {
            load_disclosure_artifacts_for_circuit(circuits_dir, lock, circuit)
                .map(|bundles| (circuit, bundles))
        })
        .collect()
}

pub fn load_disclosure_artifacts_for_circuit(
    circuits_dir: &Path,
    lock: &CircuitLockfile,
    circuit: &'static RegisteredCircuit,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir;
    let r1cs = circuits.join(circuit.artifacts.r1cs);

    let artifacts = ProverArtifacts {
        proving_key: read_artifact_file(circuits, circuit.artifacts.proving_key)?,
        circuit_graph: read_artifact_file(circuits, circuit.artifacts.graph)?,
        circuit_r1cs: std::fs::read(&r1cs).with_context(|| format!("read {}", r1cs.display()))?,
    };
    validate_artifacts(
        lock,
        &artifacts,
        circuit.artifacts.r1cs.trim_end_matches(".r1cs"),
    )?;
    Ok(artifacts)
}

pub fn load_transact_artifacts_for_stem(
    circuits_dir: &Path,
    lock: &CircuitLockfile,
    stem: CircuitStem,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir;
    let stem_str = stem.to_string();

    let artifacts = ProverArtifacts {
        proving_key: read_proving_key(circuits, &stem_str)?,
        circuit_graph: read_circuit_graph(circuits, &stem_str)?,
        circuit_r1cs: std::fs::read(circuits.join(format!("{stem_str}.r1cs"))).with_context(
            || {
                format!(
                    "read {}",
                    circuits.join(format!("{stem_str}.r1cs")).display()
                )
            },
        )?,
    };
    validate_artifacts(lock, &artifacts, &stem_str)?;
    Ok(artifacts)
}

fn read_proving_key(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    read_artifact_file(circuits, &format!("{stem}_proving_key.bin"))
}

fn read_artifact_file(circuits: &Path, file_name: &str) -> Result<Vec<u8>> {
    let path = circuits.join(file_name);
    std::fs::read(&path).with_context(|| format!("read {}", path.display()))
}

fn read_circuit_graph(circuits: &Path, stem: &str) -> Result<Vec<u8>> {
    read_artifact_file(circuits, &format!("{stem}.graph.bin"))
}

fn validate_artifacts(
    lock: &CircuitLockfile,
    artifacts: &ProverArtifacts,
    stem: &str,
) -> Result<()> {
    lock.verify_artifact(stem, "r1cs", &artifacts.circuit_r1cs)?;
    lock.verify_artifact(stem, "graph.bin", &artifacts.circuit_graph)?;
    lock.verify_artifact(stem, "proving_key.bin", &artifacts.proving_key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_locks_accept_their_own_artifacts_and_reject_other_bundles() -> Result<()> {
        let original = stellar_private_payments::circuit_lock(include_str!(
            "../../deployments/testnet/circuits.json"
        ))?;
        let stem = "selectiveDisclosure_1";
        let mut first = original.clone();
        let mut second = original;
        let hash_a = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        let hash_b = "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d";
        for (lock, hash) in [(&mut first, hash_a), (&mut second, hash_b)] {
            let entry = lock.circuits.get_mut(stem).expect("registered circuit");
            entry.r1cs = hash.into();
            entry.graph = hash.into();
            entry.proving_key = hash.into();
        }
        let bundle = |bytes: &[u8]| ProverArtifacts {
            circuit_r1cs: bytes.to_vec(),
            circuit_graph: bytes.to_vec(),
            proving_key: bytes.to_vec(),
        };
        validate_artifacts(&first, &bundle(b"a"), stem)?;
        validate_artifacts(&second, &bundle(b"b"), stem)?;
        assert!(validate_artifacts(&first, &bundle(b"b"), stem).is_err());
        assert!(validate_artifacts(&second, &bundle(b"a"), stem).is_err());
        Ok(())
    }
}
