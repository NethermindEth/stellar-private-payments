//! Groth16 proof generation
//!
//! Handles loading proving keys and generating ZK proofs from witness data.
//!
//! We cannot use ark_circom directly because it depends on
//! wasmer which doesn't work in browser WASM. Instead, we:
//! 1. Load the proving key
//! 2. Parse the R1CS file to get constraint matrices (see r1cs.rs)
//! 3. Accept pre-computed witness bytes from the JS witness calculator
//! 4. Replay constraints and generate proofs using ark-groth16

use alloc::{format, vec::Vec};
use ark_bn254::{Bn254, Fr};
use ark_ff::AdditiveGroup;
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::{
    gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;
use core::ops::AddAssign;
use wasm_bindgen::prelude::*;

use crate::{
    r1cs::R1CS,
    serialization::bytes_to_fr,
    types::{FIELD_SIZE, Groth16Proof},
};

/// A circuit that replays R1CS constraints with pre-computed witness
///
/// This is used to create proofs from:
/// 1. Pre-computed witness values (from Circom's witness calculator in JS)
/// 2. Parsed R1CS constraints (from the .r1cs file)
struct R1CSCircuit {
    /// The parsed R1CS constraints
    r1cs: R1CS,
    /// Full witness including the "one" element at index 0
    witness: Vec<Fr>,
}

impl ConstraintSynthesizer<Fr> for R1CSCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // The witness from Circom is structured as:
        // [0]: constant "1" (wire 0)
        // [1..=num_public]: public inputs (outputs first, then inputs)
        // [num_public+1..]: private witness values

        let num_public = self.r1cs.num_public as usize;
        let num_wires = self.r1cs.num_wires as usize;

        // Allocate all variables and store them for constraint generation
        let mut variables: Vec<Variable> = Vec::with_capacity(num_wires);

        // Wire 0 is always the constant 1 (already exists as Variable::One in arkworks)
        variables.push(Variable::One);

        // Allocate public inputs (wires 1..=num_public)
        for i in 1..=num_public {
            let value = if i < self.witness.len() {
                self.witness[i]
            } else {
                Fr::ZERO
            };
            let var = cs.new_input_variable(|| Ok(value))?;
            variables.push(var);
        }

        // Allocate private witnesses (wires num_public+1..)
        for i in num_public
            .checked_add(1)
            .ok_or(SynthesisError::Unsatisfiable)?..num_wires
        {
            let value = if i < self.witness.len() {
                self.witness[i]
            } else {
                Fr::ZERO
            };
            let var = cs.new_witness_variable(|| Ok(value))?;
            variables.push(var);
        }

        // Generate all constraints from R1CS
        // Each R1CS constraint is: A * B = C
        for constraint in &self.r1cs.constraints {
            // We need to capture the constraint data for the closures
            let a_terms: Vec<_> = constraint
                .a
                .terms
                .iter()
                .filter_map(|t| {
                    let idx = t.wire_id as usize;
                    if idx < variables.len() {
                        Some((t.coefficient, variables[idx]))
                    } else {
                        None
                    }
                })
                .collect();

            let b_terms: Vec<_> = constraint
                .b
                .terms
                .iter()
                .filter_map(|t| {
                    let idx = t.wire_id as usize;
                    if idx < variables.len() {
                        Some((t.coefficient, variables[idx]))
                    } else {
                        None
                    }
                })
                .collect();

            let c_terms: Vec<_> = constraint
                .c
                .terms
                .iter()
                .filter_map(|t| {
                    let idx = t.wire_id as usize;
                    if idx < variables.len() {
                        Some((t.coefficient, variables[idx]))
                    } else {
                        None
                    }
                })
                .collect();

            // Enforce A * B = C using closures
            // LinearCombination uses modular field arithmetic (cannot overflow)
            cs.enforce_r1cs_constraint(
                || {
                    let mut lc_a = lc!();
                    for (coeff, var) in &a_terms {
                        lc_a.add_assign((*coeff, *var));
                    }
                    lc_a
                },
                || {
                    let mut lc_b = lc!();
                    for (coeff, var) in &b_terms {
                        lc_b.add_assign((*coeff, *var));
                    }
                    lc_b
                },
                || {
                    let mut lc_c = lc!();
                    for (coeff, var) in &c_terms {
                        lc_c.add_assign((*coeff, *var));
                    }
                    lc_c
                },
            )?;
        }

        Ok(())
    }
}

/// Prover instance holding the loaded keys and R1CS
#[wasm_bindgen]
pub struct Prover {
    /// Groth16 proving key
    pk: ProvingKey<Bn254>,
    /// Processed verifying key (for fast verification)
    pvk: PreparedVerifyingKey<Bn254>,
    /// Parsed R1CS constraints
    r1cs: R1CS,
}

#[wasm_bindgen]
impl Prover {
    /// Create a new Prover instance from serialized keys and R1CS
    ///
    /// # Arguments
    /// * `pk_bytes` - Serialized proving key (compressed)
    /// * `r1cs_bytes` - R1CS binary file contents
    #[wasm_bindgen(constructor)]
    pub fn new(pk_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<Prover, JsValue> {
        // Deserialize proving key
        let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to load proving key: {}", e)))?;

        // Extract verifying key from proving key
        let vk = pk.vk.clone();

        // Process verifying key for faster verification
        let pvk = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk)
            .map_err(|e| JsValue::from_str(&format!("Failed to process VK: {}", e)))?;

        // Parse R1CS
        let r1cs = R1CS::parse(r1cs_bytes)?;

        Ok(Prover { pk, pvk, r1cs })
    }

    /// Get the number of public inputs expected by this circuit
    #[wasm_bindgen(getter)]
    pub fn num_public_inputs(&self) -> u32 {
        self.r1cs.num_public
    }

    /// Get the number of constraints in the circuit
    #[wasm_bindgen(getter)]
    pub fn num_constraints(&self) -> usize {
        self.r1cs.num_constraints()
    }

    /// Get the number of wires (variables) in the circuit
    #[wasm_bindgen(getter)]
    pub fn num_wires(&self) -> u32 {
        self.r1cs.num_wires
    }

    /// Get the serialized verifying key (for on-chain verification)
    #[wasm_bindgen]
    pub fn get_verifying_key(&self) -> Result<Vec<u8>, JsValue> {
        let mut vk_bytes = Vec::new();
        self.pk
            .vk
            .serialize_compressed(&mut vk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize VK: {}", e)))?;
        Ok(vk_bytes)
    }

    /// Generate a Groth16 proof from witness data
    ///
    /// # Arguments
    /// * `witness_bytes` - Full witness as Little-Endian bytes (from witness
    ///   calculator)
    ///
    /// # Returns
    /// * Groth16Proof struct with proof points
    #[wasm_bindgen]
    pub fn prove(&self, witness_bytes: &[u8]) -> Result<Groth16Proof, JsValue> {
        // Validate witness size
        if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
            return Err(JsValue::from_str(&format!(
                "Invalid witness size: {} bytes (not multiple of {})",
                witness_bytes.len(),
                FIELD_SIZE
            )));
        }

        let num_witness_elements = witness_bytes.len() / FIELD_SIZE;

        // Validate witness has enough elements
        if num_witness_elements < self.r1cs.num_wires as usize {
            return Err(JsValue::from_str(&format!(
                "Witness too short: {} elements, circuit needs {} wires",
                num_witness_elements, self.r1cs.num_wires
            )));
        }

        // Parse witness elements
        let mut witness: Vec<Fr> = Vec::with_capacity(num_witness_elements);
        for chunk in witness_bytes.chunks_exact(FIELD_SIZE) {
            witness.push(bytes_to_fr(chunk)?);
        }

        // Create circuit with R1CS and witness
        let circuit = R1CSCircuit {
            r1cs: self.r1cs.clone(),
            witness,
        };

        // Generate proof
        let mut rng = OsRng;
        let proof = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

        // Serialize proof points
        let mut a_bytes = Vec::new();
        proof
            .a
            .serialize_compressed(&mut a_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize A: {}", e)))?;

        let mut b_bytes = Vec::new();
        proof
            .b
            .serialize_compressed(&mut b_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize B: {}", e)))?;

        let mut c_bytes = Vec::new();
        proof
            .c
            .serialize_compressed(&mut c_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to serialize C: {}", e)))?;

        Ok(Groth16Proof {
            a: a_bytes,
            b: b_bytes,
            c: c_bytes,
        })
    }

    /// Generate proof and return as concatenated bytes
    ///
    /// Format: [A (compressed G1) || B (compressed G2) || C (compressed G1)]
    #[wasm_bindgen]
    pub fn prove_bytes(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        let proof = self.prove(witness_bytes)?;
        Ok(proof.to_bytes())
    }

    /// Get public inputs from witness
    ///
    /// Returns the public input portion of the witness as bytes
    #[wasm_bindgen]
    pub fn extract_public_inputs(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
            return Err(JsValue::from_str("Invalid witness size"));
        }

        let num_public = self.r1cs.num_public as usize;

        // Public inputs start at index 1 (index 0 is the "one" element)
        let start = FIELD_SIZE; // Skip element 0
        let public_size = num_public
            .checked_mul(FIELD_SIZE)
            .ok_or_else(|| JsValue::from_str("Overflow calculating public inputs size"))?;
        let end = start
            .checked_add(public_size)
            .ok_or_else(|| JsValue::from_str("Overflow calculating end offset"))?;

        if end > witness_bytes.len() {
            return Err(JsValue::from_str(&format!(
                "Witness too short: expected at least {} bytes for {} public inputs",
                end, num_public
            )));
        }

        Ok(witness_bytes[start..end].to_vec())
    }

    /// Verify a proof (for testing purposes)
    #[wasm_bindgen]
    pub fn verify(&self, proof_bytes: &[u8], public_inputs_bytes: &[u8]) -> Result<bool, JsValue> {
        // Deserialize proof
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to load proof: {}", e)))?;

        // Parse public inputs
        if !public_inputs_bytes.len().is_multiple_of(FIELD_SIZE) {
            return Err(JsValue::from_str("Invalid public inputs size"));
        }

        let num_inputs = public_inputs_bytes.len() / FIELD_SIZE;
        let expected_inputs = self
            .pk
            .vk
            .gamma_abc_g1
            .len()
            .checked_sub(1)
            .ok_or_else(|| JsValue::from_str("Invalid verifying key"))?;

        if num_inputs != expected_inputs {
            return Err(JsValue::from_str(&format!(
                "Public input count mismatch: got {}, expected {}",
                num_inputs, expected_inputs
            )));
        }

        let mut public_inputs = Vec::with_capacity(num_inputs);
        for chunk in public_inputs_bytes.chunks_exact(FIELD_SIZE) {
            public_inputs.push(bytes_to_fr(chunk)?);
        }

        // Verify
        let result = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::verify_with_processed_vk(
            &self.pvk,
            &public_inputs,
            &proof,
        )
        .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;

        Ok(result)
    }
}

/// Standalone verification function (when you only have the VK)
#[wasm_bindgen]
pub fn verify_proof(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<bool, JsValue> {
    // Deserialize verifying key
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to load VK: {}", e)))?;

    // Process VK
    let pvk = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk)
        .map_err(|e| JsValue::from_str(&format!("Failed to process VK: {}", e)))?;

    // Deserialize proof
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to load proof: {}", e)))?;

    // Parse public inputs
    if !public_inputs_bytes.len().is_multiple_of(FIELD_SIZE) {
        return Err(JsValue::from_str("Invalid public inputs size"));
    }

    let num_inputs = public_inputs_bytes.len() / FIELD_SIZE;
    let mut public_inputs = Vec::with_capacity(num_inputs);
    for chunk in public_inputs_bytes.chunks_exact(FIELD_SIZE) {
        public_inputs.push(bytes_to_fr(chunk)?);
    }

    // Verify
    let result = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::verify_with_processed_vk(
        &pvk,
        &public_inputs,
        &proof,
    )
    .map_err(|e| JsValue::from_str(&format!("Verification error: {}", e)))?;

    Ok(result)
}
