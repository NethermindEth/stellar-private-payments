//! Temp Comment

mod circom_tester;

use crate::circom_tester::{InputValue, prove_and_verify};
use anyhow::{Context, Result};
use num_bigint::{BigInt, ToBigInt};
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
    let wasm = out_dir.join("wasm/merkleProof_3_js/merkleProof_3.wasm");
    let r1cs = out_dir.join("merkleProof_3.r1cs");

    if !wasm.exists() {
        return Err(anyhow::anyhow!("WASM file not found at {}", wasm.display()));
    }
    if !r1cs.exists() {
        return Err(anyhow::anyhow!("R1CS file not found at {}", r1cs.display()));
    }

    // --- Prepare circuit inputs ---
    let mut inputs: HashMap<String, InputValue> = HashMap::new();

    let leaf_val = 123456789u64
        .to_bigint()
        .context("Failed to convert leaf value to BigInt")?;
    let root_val = 999u64
        .to_bigint()
        .context("Failed to convert root value to BigInt")?;
    let path_elems: Vec<BigInt> = vec![111u64, 222, 333]
        .into_iter()
        .map(|v| {
            v.to_bigint()
                .context("Failed to convert path element to BigInt")
        })
        .collect::<Result<_>>()?;
    let path_idx = BigInt::from(5u32);

    inputs.insert("leaf".into(), InputValue::Single(leaf_val));
    inputs.insert("root".into(), InputValue::Single(root_val));
    inputs.insert("pathElements".into(), InputValue::Array(path_elems));
    inputs.insert("pathIndices".into(), InputValue::Single(path_idx));

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
