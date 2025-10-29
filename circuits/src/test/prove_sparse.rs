//! Sparse Merkle Tree circuit test

use super::circom_tester::{InputValue, prove_and_verify};
use super::sparse_merkle_tree::{SMTMemDB, SparseMerkleTree};
use anyhow::{Context, Result};
use num_bigint::{BigInt, BigUint, ToBigInt};
use std::{collections::HashMap, path::PathBuf};

/// Proof data for Sparse Merkle Tree verification
pub struct SMTProof {
    /// Whether the key was found
    pub found: bool,
    /// Sibling hashes along the path
    pub siblings: Vec<BigUint>,
    /// The found value
    pub found_value: BigUint,
    /// The key that was not found
    pub not_found_key: BigUint,
    /// The value that was not found
    pub not_found_value: BigUint,
    /// Whether the old value was zero
    pub is_old0: bool,
    /// The root of the SMT
    pub root: BigUint,
}

fn run_case(wasm: &PathBuf, r1cs: &PathBuf, queried_key: BigUint, max_levels: usize) -> Result<()> {
    let smt_proof = prepare_smt_proof(&queried_key, max_levels);

    // Map SMT proof to circuit inputs
    let enabled = BigInt::from(1u32);
    let root = smt_proof
        .root
        .clone()
        .to_bigint()
        .expect("Failed to convert root to BigInt");

    // The function to use for the SMT (0 = inclusion, 1 = non-inclusion)
    let fnc = if smt_proof.found {
        BigInt::from(0u32)
    } else {
        BigInt::from(1u32)
    };

    // Compute (oldKey, oldValue, isOld0, key, value) according to what smtverifier.circom expects
    let (old_key, old_value, is_old0, key_for_circuit, value_for_circuit) = if smt_proof.found {
        // Inclusion proof
        (
            queried_key.clone(),
            smt_proof.found_value.clone(),
            BigInt::from(0u32),
            queried_key.clone(),
            smt_proof.found_value.clone(),
        )
    } else if smt_proof.is_old0 {
        // Non-inclusion: empty path
        (
            queried_key.clone(),
            BigUint::from(0u32),
            BigInt::from(1u32),
            queried_key.clone(),
            BigUint::from(0u32),
        )
    } else {
        // Non-inclusion: collision with existing leaf
        (
            smt_proof.not_found_key.clone(),
            smt_proof.not_found_value.clone(),
            BigInt::from(0u32),
            queried_key.clone(),
            BigUint::from(0u32),
        )
    };

    let siblings_bigint: Vec<BigInt> = smt_proof
        .siblings
        .iter()
        .map(|v| v.to_bigint().context("Failed to convert sibling to BigInt"))
        .collect::<Result<_>>()?;

    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert("enabled".into(), InputValue::Single(enabled));
    inputs.insert("root".into(), InputValue::Single(root));
    inputs.insert("siblings".into(), InputValue::Array(siblings_bigint));
    inputs.insert(
        "oldKey".into(),
        InputValue::Single(old_key.to_bigint().expect("oldKey -> BigInt")),
    );
    inputs.insert(
        "oldValue".into(),
        InputValue::Single(old_value.to_bigint().expect("oldValue -> BigInt")),
    );
    inputs.insert("isOld0".into(), InputValue::Single(is_old0));
    inputs.insert(
        "key".into(),
        InputValue::Single(key_for_circuit.to_bigint().expect("key -> BigInt")),
    );
    inputs.insert(
        "value".into(),
        InputValue::Single(value_for_circuit.to_bigint().expect("value -> BigInt")),
    );
    inputs.insert("fnc".into(), InputValue::Single(fnc));

    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    assert!(res.verified, "Proof did not verify for key {queried_key}");

    Ok(())
}

#[tokio::test]
async fn test_sparse_merkle_tree_membership_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/sparse_merkle_tree_js/sparse_merkle_tree.wasm");
    let r1cs = out_dir.join("sparse_merkle_tree.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX ===
    const MAX_LEVELS: usize = 254;

    // Inclusion cases
    let inclusion_keys = [0u32, 1, 50, 99];
    for k in inclusion_keys {
        run_case(&wasm, &r1cs, BigUint::from(k), MAX_LEVELS)
            .with_context(|| format!("Inclusion case failed for key {k}"))?;
    }

    // Non-inclusion cases
    let non_inclusion_keys = [100u32, 200, 123_456];
    for k in non_inclusion_keys {
        run_case(&wasm, &r1cs, BigUint::from(k), MAX_LEVELS)
            .with_context(|| format!("Non-inclusion case failed for key {k}"))?;
    }

    Ok(())
}

// Prepare data for the Circom circuit
fn prepare_smt_proof(key: &BigUint, max_levels: usize) -> SMTProof {
    let db = SMTMemDB::new();
    let mut smt = SparseMerkleTree::new(db, BigUint::from(0u32));

    for i in 0u32..100 {
        smt.insert(&BigUint::from(i), &BigUint::from(i))
            .expect("Failed to insert key");
    }

    let find_result = smt.find(key).expect("Failed to find key");

    // Pad siblings with zeros to reach max_levels
    let mut siblings = find_result.siblings.clone();
    while siblings.len() < max_levels {
        siblings.push(BigUint::from(0u32));
    }

    SMTProof {
        found: find_result.found,
        siblings,
        found_value: find_result.found_value,
        not_found_key: find_result.not_found_key,
        not_found_value: find_result.not_found_value,
        is_old0: find_result.is_old0,
        root: smt.root().clone(),
    }
}
