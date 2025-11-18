//! Poseidon2 circuit test

use super::circom_tester::prove_and_verify;
use crate::test::utils::circom_tester::Inputs;
use crate::test::utils::general::load_artifacts;
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::path::PathBuf;

fn run_case(wasm: &PathBuf, r1cs: &PathBuf, inputs_pair: (u64, u64)) -> Result<()> {
    // Prepare circuit inputs
    let mut inputs = Inputs::new();
    let value_inputs: Vec<BigInt> = vec![BigInt::from(inputs_pair.0), BigInt::from(inputs_pair.1)];
    inputs.set("inputs", value_inputs);

    let res = prove_and_verify(wasm, r1cs, &inputs)?;

    assert!(
        res.verified,
        "Proof did not verify for inputs {inputs_pair:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_poseidon2_hash_2_matrix() -> anyhow::Result<()> {
    // === PATH SETUP ===
    let (wasm, r1cs) = load_artifacts("poseidon2_hash_2")?;

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
