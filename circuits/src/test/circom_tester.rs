use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig, CircomReduction};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_std::rand::thread_rng;
use num_bigint::BigInt;
use std::{collections::HashMap, path::Path};

use anyhow::{Result, anyhow};
use ark_snark::SNARK;

/// Represents possible Circom circuit input types.
/// - `Single`: a single field element (BigInt).
/// - `Array`: a list of field elements, used for signals like `[input[i]]`.
#[derive(Clone, Debug)]
pub enum InputValue {
    Single(BigInt),
    Array(Vec<BigInt>),
}

/// Encapsulates the result of a Circom proof generation and verification process.
/// Contains the proof, verification key, public inputs, and verification result.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CircomResult {
    pub verified: bool,
    pub public_inputs: Vec<Fr>, /* this can be a trait but we dont care about generalising that
                                 * much now */
    pub proof: Proof<Bn254>,
    pub vk: VerifyingKey<Bn254>,
}

/// Builds, proves, and verifies a Circom circuit using Groth16 over BN254.
///
/// # Arguments
/// * `wasm_path` - Path to the compiled Circom `.wasm` file.
/// * `r1cs_path` - Path to the Circom `.r1cs` constraint file.
/// * `inputs` - A map of signal names to their respective `InputValue`s.
///
/// # Returns
/// * `CircomResult` containing the proof, vk, public inputs, and verification result.
///
/// # Errors
/// Returns `anyhow::Error` if any step of setup, proof, or verification fails.
pub fn prove_and_verify(
    wasm_path: impl AsRef<Path>,
    r1cs_path: impl AsRef<Path>,
    inputs: &HashMap<String, InputValue>,
) -> Result<CircomResult> {
    // === 1. Load the Circom circuit configuration ===
    // This parses both the `.wasm` and `.r1cs` files so that we can
    // construct and run the circuit with given inputs.
    let cfg = CircomConfig::<Fr>::new(wasm_path.as_ref(), r1cs_path.as_ref())
        .map_err(|e| anyhow!("CircomConfig error: {e}"))?;

    // === 2. Create a circuit builder ===
    // The builder is used to push inputs and prepare the circuit.
    let mut builder = CircomBuilder::new(cfg);

    // === 3. Add inputs to the builder ===
    // Loop through each input signal and feed it into the circuit.
    for (signal, value) in inputs {
        match value {
            // For a single BigInt value
            InputValue::Single(v) => builder.push_input(signal, v.clone()),
            // For an array of BigInts (e.g., arrays in Circom)
            InputValue::Array(arr) => {
                for v in arr.iter() {
                    builder.push_input(signal, v.clone())
                }
            }
        }
    }

    // === 4. Prepare the empty circuit for setup ===
    // This builds the "shape" of the circuit without specific inputs.
    let empty = builder.setup();
    let mut rng = thread_rng();

    // === 5. Generate proving and verification keys ===
    // Performs the circuit-specific Groth16 setup phase.
    let (pk, vk) = Groth16::<Bn254, CircomReduction>::circuit_specific_setup(empty, &mut rng)
        .map_err(|e| anyhow!("circuit_specific_setup failed: {e}"))?;

    // === 6. Build the actual circuit with real inputs ===
    let circuit = builder.build().map_err(|e| anyhow!("build failed: {e}"))?;

    // === 7. Generate the zero-knowledge proof ===
    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit.clone(), &mut rng)
        .map_err(|e| anyhow!("prove failed: {e}"))?;

    // === 8. Extract public inputs from the circuit ===
    // These correspond to Circom's `signal output` or `signal public` values.
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or_else(|| anyhow!("get_public_inputs returned None"))?;

    // === 9. Process the verification key ===
    // The processed VK is used for faster proof verification.
    let pvk = Groth16::<Bn254, CircomReduction>::process_vk(&vk)
        .map_err(|e| anyhow!("process_vk failed: {e}"))?;

    // === 10. Verify the proof ===
    // Confirms that the proof is valid for the given public inputs.
    let verified =
        Groth16::<Bn254, CircomReduction>::verify_with_processed_vk(&pvk, &public_inputs, &proof)
            .map_err(|e| anyhow!("verify_with_processed_vk failed: {e}"))?;

    // === 11. Return structured result ===
    Ok(CircomResult {
        verified,
        public_inputs,
        proof,
        vk,
    })
}
