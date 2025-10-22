//! Temp Comment

use super::circom_tester::{InputValue, prove_and_verify};
use anyhow::{Context, Result};
use num_bigint::BigInt;
use std::{collections::HashMap, env, path::PathBuf};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // Nice error reporting
    color_eyre::install().ok();

    // --- Load environment variable safely ---
    let out_dir = PathBuf::from(
        env::var("CIRCUIT_OUT_DIR").context("Environment variable CIRCUIT_OUT_DIR is not set")?,
    );

    // --- Resolve file paths ---
    let wasm = out_dir.join("wasm/poseidon2_hash_2_js/poseidon2_hash_2.wasm");
    let r1cs = out_dir.join("poseidon2_hash_2.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // --- Prepare circuit inputs ---
    let mut inputs: HashMap<String, InputValue> = HashMap::new();

    let value_inputs: Vec<BigInt> = vec![BigInt::from(1u32), BigInt::from(2u32)];

    inputs.insert("inputs".into(), InputValue::Array(value_inputs));

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
