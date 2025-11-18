//! Poseidon2 circuit test

use super::circom_tester::prove_and_verify;
use crate::test::utils::circom_tester::Inputs;
use crate::test::utils::general::load_artifacts;
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::path::PathBuf;

fn run_case_hash(
    wasm: &PathBuf,
    r1cs: &PathBuf,
    inputs_pair: (u64, u64),
    domain_separation: u64,
) -> Result<()> {
    // Prepare circuit inputs
    let mut inputs = Inputs::new();
    let value_inputs: Vec<BigInt> = vec![BigInt::from(inputs_pair.0), BigInt::from(inputs_pair.1)];
    let domain_separation: BigInt = BigInt::from(domain_separation);
    inputs.set("inputs", value_inputs);
    inputs.set("domainSeparation", domain_separation);

    let res =
        prove_and_verify(wasm, r1cs, &inputs).context("Failed to prove and verify circuit")?;

    assert!(
        res.verified,
        "Proof did not verify for inputs {inputs_pair:?}"
    );

    Ok(())
}

fn run_case_compress(wasm: &PathBuf, r1cs: &PathBuf, inputs_pair: (u64, u64)) -> Result<()> {
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
async fn test_poseidon2_hash_2_matrix() -> Result<()> {
    // === PATH SETUP ===
    let (wasm, r1cs) = load_artifacts("poseidon2_hash_2")?;

    // === TEST MATRIX ===
    let cases: &[((u64, u64), u64)] = &[
        ((0, 0), 0),
        ((1, 2), 1),
        ((2, 1), 2),
        ((42, 1337), 3),
        ((u64::from(u32::MAX), 7), 4),
        ((123456789, 987654321), 5),
        ((2025, 10), 6),
    ];

    for (pair, domain_separation) in cases {
        run_case_hash(&wasm, &r1cs, *pair, *domain_separation)
            .with_context(|| format!("Poseidon2 case failed: {pair:?}",))?;
    }

    Ok(())
}

#[tokio::test]
async fn test_poseidon2_compression() -> Result<()> {
    // === PATH SETUP ===
    let out_dir = PathBuf::from(env!("CIRCUIT_OUT_DIR"));
    let wasm = out_dir.join("wasm/poseidon2_compress_js/poseidon2_compress.wasm");
    let r1cs = out_dir.join("poseidon2_compress.r1cs");

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

    for pair in cases {
        run_case_compress(&wasm, &r1cs, *pair)
            .with_context(|| format!("Poseidon2 case failed: {pair:?}",))?;
    }

    Ok(())
}
