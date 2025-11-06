use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use std::{collections::HashMap, path::Path};

use crate::test::utils::circom_tester::InputValue::Object;
use anyhow::{Result, anyhow};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub enum InputValue {
    Single(BigInt),
    Array(Vec<BigInt>),
    Object(HashMap<String, InputValue>), // Ideally this would be  Array(Vec<InputValue>) but we will need to change all the tests. Lets raise an issue for now
}
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CircomResult {
    pub verified: bool,
    pub public_inputs: Vec<Fr>, /* this can be a trait but we dont care about generalising that
                                 * much now */
    pub proof: Proof<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

fn push_value(builder: &mut CircomBuilder<Fr>, path: &str, value: &InputValue) {
    match value {
        InputValue::Single(v) => {
            builder.push_input(path, v.clone());
        }
        InputValue::Array(arr) => {
            for v in arr.iter() {
                builder.push_input(path, v.clone())
            }
        }
        InputValue::Object(map) => {
            for (k, v) in map {
                let child = if let Ok(idx) = k.parse::<usize>() {
                    // numeric key -> array index
                    if path.is_empty() {
                        format!("[{idx}]")
                    } else {
                        format!("{path}[{idx}]")
                    }
                } else {
                    // non-numeric key -> struct field
                    if path.is_empty() {
                        k.to_string()
                    } else {
                        format!("{path}.{k}")
                    }
                };
                push_value(builder, &child, v);
            }
        }
    }
}

pub fn obj(mut kv: Vec<(&str, InputValue)>) -> InputValue {
    let mut m = HashMap::new();
    for (k, v) in kv.drain(..) {
        m.insert(k.to_string(), v);
    }
    Object(m)
}

pub fn prove_and_verify(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &HashMap<String, InputValue>,
) -> Result<CircomResult> {
    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    let mut builder = CircomBuilder::new(cfg);

    // for (signal, value) in inputs {
    //     match value {
    //         InputValue::Single(v) => builder.push_input(signal, v.clone()),
    //         InputValue::Array(arr) => {
    //             for v in arr.iter() {
    //                 builder.push_input(signal, v.clone())
    //             }
    //         }
    //
    //     }
    // }
    for (signal, value) in inputs {
        push_value(&mut builder, signal, value);
    }

    let empty = builder.setup();
    let mut rng = thread_rng();

    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    let circuit = builder.build().map_err(|e| anyhow!("build failed: {e}"))?;

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();

    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    // Extract public inputs and verify
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow!("get_public_inputs returned None"))?;
    let pvk = Groth16::<Bn254, CircomReduction>::process_vk(&vk)
        .map_err(|e| anyhow!("process_vk failed: {e}"))?;
    let verified =
        Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;

    Ok(CircomResult {
        verified,
        public_inputs,
        proof,
        vk,
    })
}
