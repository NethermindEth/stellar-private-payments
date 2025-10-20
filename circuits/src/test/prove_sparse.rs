//! Temp Comment
mod circom_tester;

use crate::circom_tester::{InputValue, prove_and_verify};
use anyhow::{Context, Result};
use circuits::test::utils::sparse_merkle_tree::{SMTMemDB, SparseMerkleTree};
use num_bigint::{BigInt, BigUint, ToBigInt};
use std::{collections::HashMap, env, path::PathBuf};

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
    /// The function to use for the SMT
    pub fnc: u8, // 0 = proof of inclusion, 1 = proof of non-inclusion
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Nice error reporting
    color_eyre::install().ok();

    // --- Load environment variable safely ---
    let out_dir = PathBuf::from(
        env::var("CIRCUIT_OUT_DIR").context("Environment variable CIRCUIT_OUT_DIR is not set")?,
    );

    // --- Resolve file paths ---
    let wasm = out_dir.join("wasm/sparse_merkle_tree_js/sparse_merkle_tree.wasm");
    let r1cs = out_dir.join("sparse_merkle_tree.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // --- Prepare circuit inputs ---
    let mut inputs: HashMap<String, InputValue> = HashMap::new();

    // Insert inputs for sparse merkle tree non-membership proof verification
    let queried_key = BigUint::from(200u32); // NOT in the SMT
    let smt_proof = prepare_smt_proof(&queried_key, 254);

    // Map SMT proof to circuit inputs
    let enabled = BigInt::from(1u32);
    let root = smt_proof
        .root
        .clone()
        .to_bigint()
        .expect("Failed to convert root to BigInt");
    let siblings = smt_proof.siblings.clone();
    let fnc = if smt_proof.found {
        BigInt::from(0u32)
    } else {
        BigInt::from(1u32)
    }; // 0=inclusion, 1=non-inclusion

    // Compute (oldKey, oldValue, isOld0, key, value) according to what
    // smtverifier.circom expects
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
            BigUint::from(0u32), // Not found
        )
    } else {
        // Non-inclusion: collision with existing leaf
        (
            smt_proof.not_found_key.clone(),
            smt_proof.not_found_value.clone(),
            BigInt::from(0u32),
            queried_key.clone(),
            BigUint::from(0u32), // Not found
        )
    };
    let siblings_bigint: Vec<BigInt> = siblings
        .into_iter()
        .map(|v| {
            v.to_bigint()
                .context("Failed to sibling path element to BigInt")
        })
        .collect::<Result<_>>()?;

    inputs.insert("enabled".into(), InputValue::Single(enabled));
    inputs.insert("root".into(), InputValue::Single(root));
    inputs.insert("siblings".into(), InputValue::Array(siblings_bigint));
    inputs.insert(
        "oldKey".into(),
        InputValue::Single(
            old_key
                .to_bigint()
                .expect("Failed to convert old key to BigInt"),
        ),
    );
    inputs.insert(
        "oldValue".into(),
        InputValue::Single(
            old_value
                .to_bigint()
                .expect("Failed to convert old value to BigInt"),
        ),
    );
    inputs.insert("isOld0".into(), InputValue::Single(is_old0));
    inputs.insert(
        "key".into(),
        InputValue::Single(
            key_for_circuit
                .to_bigint()
                .expect("Failed to convert key to BigInt"),
        ),
    );
    inputs.insert(
        "value".into(),
        InputValue::Single(
            value_for_circuit
                .to_bigint()
                .expect("Failed to convert value to BigInt"),
        ),
    );
    inputs.insert("fnc".into(), InputValue::Single(fnc));

    // --- Run proof and verification ---
    let res =
        prove_and_verify(&wasm, &r1cs, &inputs).context("Failed to prove and verify circuit")?;

    // --- Display results ---
    println!("Verification: {}", res.verified);
    if !res.public_inputs.is_empty() {
        println!("Public inputs ({}):", res.public_inputs.len());
        for (i, pi) in res.public_inputs.iter().enumerate() {
            println!("  [{i}] {pi}");
        }
    }
    println!("Proof verified: {}", res.verified);

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
        fnc: if find_result.found { 0 } else { 1 }, /* 0 = proof of inclusion, 1 = proof of
                                                     * non-inclusion */
    }
}
