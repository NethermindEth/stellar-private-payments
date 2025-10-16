//! Temp Comment

mod circom_tester;

use std::collections::HashMap;
use std::path::PathBuf;

use ark_snark::SNARK;
use num_bigint::{BigInt, ToBigInt};
use std::env;

use anyhow::{Result};
use crate::circom_tester::{prove_and_verify, InputValue};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install().ok();

    let out_dir = PathBuf::from(env::var("CIRCUIT_OUT_DIR")?);
    let wasm = out_dir.join("wasm/merkleProof_3_js/merkleProof_3.wasm");
    let r1cs = out_dir.join("merkleProof_3.r1cs");

    let mut inputs: HashMap<String, InputValue> = HashMap::new();
    inputs.insert("leaf".into(), InputValue::Single(123456789u64.to_bigint().unwrap()));
    inputs.insert("root".into(), InputValue::Single(999u64.to_bigint().unwrap()));
    inputs.insert(
        "pathElements".into(),
        InputValue::Array(vec![111, 222, 333].into_iter().map(|v| v.to_bigint().unwrap()).collect()),
    );
    inputs.insert("pathIndices".into(), InputValue::Single(BigInt::from(5u32)));

    let res = prove_and_verify(&wasm, &r1cs, &inputs)?;
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
