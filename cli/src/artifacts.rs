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
    keys_dir: &Path,
    lock: &CircuitLockfile,
) -> Result<Vec<(CircuitStem, ProverArtifacts)>> {
    CircuitStem::all_transact_stems()
        .into_iter()
        .map(|stem| {
            load_transact_artifacts_for_stem(circuits_dir, keys_dir, lock, stem)
                .map(|artifacts| (stem, artifacts))
        })
        .collect()
}

pub fn load_disclosure_artifacts(
    circuits_dir: &Path,
    keys_dir: &Path,
    lock: &CircuitLockfile,
) -> Result<Vec<(&'static RegisteredCircuit, ProverArtifacts)>> {
    DISCLOSURE_CIRCUITS
        .into_iter()
        .map(|circuit| {
            load_disclosure_artifacts_for_circuit(circuits_dir, keys_dir, lock, circuit)
                .map(|bundles| (circuit, bundles))
        })
        .collect()
}

pub fn load_disclosure_artifacts_for_circuit(
    circuits_dir: &Path,
    keys_dir: &Path,
    lock: &CircuitLockfile,
    circuit: &'static RegisteredCircuit,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir;

    let artifacts = ProverArtifacts {
        proving_key: read_artifact_file(circuits, keys_dir, circuit.artifacts.proving_key)?,
        circuit_graph: read_artifact_file(circuits, keys_dir, circuit.artifacts.graph)?,
        circuit_r1cs: read_artifact_file(circuits, keys_dir, circuit.artifacts.r1cs)?,
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
    keys_dir: &Path,
    lock: &CircuitLockfile,
    stem: CircuitStem,
) -> Result<ProverArtifacts> {
    let circuits = circuits_dir;
    let stem_str = stem.to_string();

    let artifacts = ProverArtifacts {
        proving_key: read_artifact_file(
            circuits,
            keys_dir,
            &format!("{stem_str}_proving_key.bin"),
        )?,
        circuit_graph: read_artifact_file(circuits, keys_dir, &format!("{stem_str}.graph.bin"))?,
        circuit_r1cs: read_artifact_file(circuits, keys_dir, &format!("{stem_str}.r1cs"))?,
    };
    validate_artifacts(lock, &artifacts, &stem_str)?;
    Ok(artifacts)
}

fn read_artifact_file(circuits: &Path, keys: &Path, file_name: &str) -> Result<Vec<u8>> {
    let primary = circuits.join(file_name);
    let fallback = keys.join(file_name);
    for path in [&primary, &fallback] {
        match std::fs::read(path) {
            Ok(bytes) => return Ok(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        }
        if primary == fallback {
            break;
        }
    }
    anyhow::bail!(
        "missing circuit artifact {file_name}; searched {} and {}. Proofs require .r1cs, .graph.bin and _proving_key.bin files matching the deployment's circuits.json. In a repository checkout, run `make circuits` for R1CS, then pass --circuits-dir <repo>/target/circuits-artifacts if needed; missing files fall back to the selected deployment's circuit_keys/. Alternatively pass --circuits-dir with a complete artifact bundle.",
        primary.display(),
        fallback.display()
    )
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
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Result<Self> {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let root =
                std::env::temp_dir().join(format!("spp-artifacts-{}-{nonce}", std::process::id()));
            std::fs::create_dir_all(&root)?;
            Ok(Self(root))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn repository_config() -> Result<crate::config::CliConfig> {
        crate::config::CliConfig::load(
            None,
            None,
            crate::config::CliConfigOverrides {
                deployment_path: Some(
                    Path::new(env!("CARGO_MANIFEST_DIR")).join("../deployments/testnet"),
                ),
                ..Default::default()
            },
        )
    }

    #[test]
    fn default_and_override_paths_resolve_split_and_complete_bundles() -> Result<()> {
        let scratch = Scratch::new()?;
        let root = &scratch.0;
        let deployment = root.join("deployments/custom");
        let keys = deployment.join("circuit_keys");
        let output = root.join("target/circuits-artifacts");
        std::fs::create_dir_all(&keys)?;
        std::fs::create_dir_all(&output)?;
        std::fs::create_dir_all(root.join("circuits"))?;
        std::fs::write(root.join("Cargo.toml"), "")?;
        std::fs::write(root.join("circuits/Cargo.toml"), "")?;
        let mut config = repository_config()?;
        config.deployment_source = deployment.join("deployments.json").display().to_string();
        assert_eq!(config.circuits_dir_path(), output);
        assert_eq!(config.circuit_keys_dir_path(), keys);
        let mut lock = stellar_private_payments::circuit_lock(include_str!(
            "../../deployments/testnet/circuits.json"
        ))?;
        let hash = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
        for entry in lock.circuits.values_mut() {
            entry.r1cs = hash.into();
            entry.graph = hash.into();
            entry.proving_key = hash.into();
        }
        for stem in lock.circuits.keys() {
            std::fs::write(output.join(format!("{stem}.r1cs")), b"a")?;
            std::fs::write(keys.join(format!("{stem}.graph.bin")), b"a")?;
            std::fs::write(keys.join(format!("{stem}_proving_key.bin")), b"a")?;
        }
        assert_eq!(
            load_transact_artifacts(&config.circuits_dir_path(), &keys, &lock)?.len(),
            CircuitStem::all_transact_stems().len()
        );
        assert_eq!(
            load_disclosure_artifacts(&config.circuits_dir_path(), &keys, &lock)?.len(),
            4
        );
        // Explicit R1CS-only output retains the deployment-key fallback.
        config.circuits_dir = Some(output.clone());
        load_disclosure_artifacts(&config.circuits_dir_path(), &keys, &lock)?;
        // A corrupt primary must not silently fall back to a good committed
        // key.
        let primary_key = output.join("selectiveDisclosure_1_proving_key.bin");
        std::fs::write(&primary_key, b"corrupt")?;
        assert!(
            load_disclosure_artifacts(&output, &keys, &lock)
                .expect_err("corrupt primary")
                .to_string()
                .contains("hash mismatch")
        );
        std::fs::remove_file(primary_key)?;
        std::fs::remove_file(output.join("selectiveDisclosure_1.r1cs"))?;
        let error = load_disclosure_artifacts(&output, &keys, &lock)
            .expect_err("missing R1CS")
            .to_string();
        for hint in [".r1cs", "--circuits-dir", "make circuits"] {
            assert!(error.contains(hint), "{error}");
        }
        std::fs::write(output.join("selectiveDisclosure_1.r1cs"), b"a")?;
        // A complete installed bundle takes precedence and needs no keys
        // directory.
        let installed = deployment.join("circuits");
        std::fs::create_dir(&installed)?;
        for source in [&output, &keys] {
            for entry in std::fs::read_dir(source)? {
                let entry = entry?;
                std::fs::copy(entry.path(), installed.join(entry.file_name()))?;
            }
        }
        std::fs::remove_dir_all(&keys)?;
        config.circuits_dir = None;
        assert_eq!(config.circuits_dir_path(), installed);
        load_transact_artifacts(&installed, &keys, &lock)?;
        load_disclosure_artifacts(&installed, &keys, &lock)?;
        config.circuits_dir = Some(output.clone());
        assert_eq!(config.circuits_dir_path(), output);
        Ok(())
    }

    #[test]
    #[ignore = "requires make circuits and committed deployment keys; generates an offline proof"]
    fn repository_default_generates_and_verifies_a_proof() -> Result<()> {
        use stellar_private_payments::{
            prover::ProverEngine,
            types::{
                EncryptionPublicKey, ExtAmount, Field, GvkMode, NoteAmount, NotePrivateKey,
                PolicyFlags,
            },
            zk::flows::{TransactOutput, TransactParams},
        };
        let config = repository_config()?;
        let artifacts = load_transact_artifacts_for_stem(
            &config.circuits_dir_path(),
            &config.circuit_keys_dir_path(),
            &config.circuit_lock()?,
            CircuitStem::transact(PolicyFlags::EMPTY, GvkMode::Off),
        )?;
        let engine = ProverEngine::new(
            &artifacts.proving_key,
            &artifacts.circuit_graph,
            &artifacts.circuit_r1cs,
        )?;
        let pool = &config.deployment.pools[0];
        let proof = engine.prove_transact(TransactParams {
            priv_key: NotePrivateKey([1; 32]),
            encryption_pubkey: EncryptionPublicKey([2; 32]),
            pool_root: Field::ZERO,
            pool_address: pool.pool_contract_id.clone(),
            token_address: pool.token_contract_id.clone(),
            ext_recipient: pool.pool_contract_id.clone(),
            ext_amount: ExtAmount::from(10),
            inputs: Vec::new(),
            outputs: vec![TransactOutput {
                amount: NoteAmount::from(10),
                blinding: Field::try_from_le_bytes([3; 32])?,
                recipient_note_pubkey: None,
                recipient_encryption_pubkey: None,
            }],
            membership_proof: None,
            non_membership_proof: None,
            tree_depth: 20,
            asp_depth: 10,
            smt_depth: 10,
            policy_flags: PolicyFlags::EMPTY,
            gvk_mode: GvkMode::Off,
            admin_view_key: None,
        })?;
        // ProverEngine also verifies the generated proof before returning it.
        assert_eq!(proof.proof_uncompressed.len(), 256);
        Ok(())
    }
}
