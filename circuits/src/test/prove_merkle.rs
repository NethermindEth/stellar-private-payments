//! Temp Comment

use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::thread_rng;
use num_bigint::ToBigInt;

use anyhow::{Result, anyhow};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    color_eyre::install().ok();

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let wasm = root.join("compiled/wasm/merkleProof_3_js/merkleProof_3.wasm");
    let r1cs = root.join("compiled/merkleProof_3.r1cs");

    let cfg = CircomConfig::<Fr>::new(wasm, r1cs).map_err(|e| anyhow!(e))?;
    let mut builder = CircomBuilder::new(cfg);

    // Input edit

    builder.push_input("leaf", 123456789.to_bigint().expect(""));
    builder.push_input("root", 999u64.to_bigint().expect(""));
    for v in [111, 222, 333] {
        builder.push_input("pathElements", v.to_bigint().expect(""));
    }
    builder.push_input("pathIndices", 5.to_bigint().expect(""));

    let empty = builder.setup();
    let mut rng = thread_rng();

    let (pk, vk) =
        Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng).expect("");

    let circuit = builder.build().expect("");
    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng).expect("");

    let public_inputs = circuit.get_public_inputs().expect("");

    let pvk = Groth16::<Bn254, CircomReduction>::process_vk(&vk).expect("");

    let ok =
        Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .expect("");

    println!("Verification: {}", ok);

    if !public_inputs.is_empty() {
        println!("Public inputs ({}):", public_inputs.len());
        for (i, pi) in public_inputs.iter().enumerate() {
            println!("  [{}] {}", i, pi);
        }
    }
    println!("Proof verified");

    Ok(())
}
