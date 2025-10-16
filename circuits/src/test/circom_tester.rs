use std::collections::HashMap;
use std::path::Path;
use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use num_bigint::BigInt;
use ark_std::rand::thread_rng;


use anyhow::{Result, anyhow};
use ark_snark::SNARK;

#[derive(Clone, Debug)]
pub enum InputValue {
    Single(BigInt),
    Array(Vec<BigInt>),
}

#[derive(Clone, Debug)]
pub struct CircomResult {
    pub verified: bool,
    pub public_inputs: Vec<Fr>, // this can be a trait but we dont care about generalising that much now
    pub proof: Proof<Bn254>,
    pub vk: VerifyingKey<Bn254>
}

pub fn prove_and_verify(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &HashMap<String, InputValue>,
) -> Result<CircomResult> {

    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let mut builder = CircomBuilder::new(cfg);

    for (signal, value) in inputs {
        match value {
            InputValue::Single(v) => {
                builder
                    .push_input(signal, v.clone())
            }
            InputValue::Array(arr) => {
                for (idx, v) in arr.iter().enumerate() {
                    builder
                        .push_input(signal, v.clone())
                }
            }
        }
    }

    let empty = builder
        .setup();
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    let circuit = builder.build().map_err(|e| anyhow!("build failed: {e}"))?;
    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    // Extract public inputs and verify
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow!("get_public_inputs returned None"))?;
    let pvk =
        Groth16::<Bn254, CircomReduction>::process_vk(&vk).map_err(|e| anyhow!("process_vk failed: {e}"))?;
    let verified = Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &proof,
    )
        .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;

    Ok(CircomResult {
        verified,
        public_inputs,
        proof,
        vk,
    })
}