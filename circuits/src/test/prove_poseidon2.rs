//! Poseidon2 circuit test

use super::circom_tester::{InputValue, prove_and_verify};
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::{collections::HashMap, path::PathBuf};

fn run_case(wasm: &PathBuf, r1cs: &PathBuf, inputs_pair: (u64, u64)) -> Result<()> {
    // Prepare circuit inputs
    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    let value_inputs: Vec<BigInt> = vec![BigInt::from(inputs_pair.0), BigInt::from(inputs_pair.1)];
    inputs.insert("inputs".into(), InputValue::Array(value_inputs));

    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    assert!(
        res.verified,
        "Proof did not verify for inputs {inputs_pair:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_poseidon2_hash_2_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/poseidon2_hash_2_js/poseidon2_hash_2.wasm");
    let r1cs = out_dir.join("poseidon2_hash_2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // === TEST MATRIX ===
    let cases: &[(u64, u64)] = &[
        (0, 0),
        (1, 2),
        (2, 1),
        (42, 1337),
        (u64::from(u32::MAX), 7),
        (123456789, 987654321),
        (2025, 10),
    ];

    for &pair in cases {
        run_case(&wasm, &r1cs, pair)
            .with_context(|| format!("Poseidon2 case failed: {pair:?}",))?;
    }

    Ok(())
}
