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

use crate::{
    r1cs::R1CS,
    serialization::bytes_to_fr,
    types::{FIELD_SIZE, Groth16Proof},
};
use alloc::{format, vec::Vec};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
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

// Soroban-compatible encoding helpers.
// Soroban's BN254 G2 uses c1||c0 (imaginary||real) ordering, while arkworks
// uses c0||c1.

/// Converts a BigInteger to 32-byte big-endian representation.
fn bigint_to_be_32<B: BigInteger>(value: B) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..].copy_from_slice(&bytes[..bytes.len().min(32)]);
    out
}

/// Converts a G1Affine point to 64-byte uncompressed big-endian format.
/// Format: x (32 bytes BE) || y (32 bytes BE)
fn g1_bytes_uncompressed(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    let x_bytes = bigint_to_be_32(p.x.into_bigint());
    let y_bytes = bigint_to_be_32(p.y.into_bigint());
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

/// Converts a G2Affine point to 128-byte uncompressed format with Soroban
/// ordering. Soroban/Ethereum-compatible: c1 (imaginary) || c0 (real) for each
/// coordinate. Format: x.c1 || x.c0 || y.c1 || y.c0 (each 32 bytes BE)
fn g2_bytes_uncompressed(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    let x0 = bigint_to_be_32(p.x.c0.into_bigint());
    let x1 = bigint_to_be_32(p.x.c1.into_bigint());
    let y0 = bigint_to_be_32(p.y.c0.into_bigint());
    let y1 = bigint_to_be_32(p.y.c1.into_bigint());

    // Soroban ordering: c1 || c0 for each coordinate
    out[..32].copy_from_slice(&x1);
    out[32..64].copy_from_slice(&x0);
    out[64..96].copy_from_slice(&y1);
    out[96..].copy_from_slice(&y0);
    out
}

/// Converts a compressed arkworks proof to uncompressed bytes for Soroban
/// contracts. Output: A (64 bytes) || B (128 bytes) || C (64 bytes) = 256 bytes
/// total
fn proof_to_uncompressed_bytes(proof: &Proof<Bn254>) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&g1_bytes_uncompressed(&proof.a));
    out.extend_from_slice(&g2_bytes_uncompressed(&proof.b));
    out.extend_from_slice(&g1_bytes_uncompressed(&proof.c));
    out
}

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
        if self.witness.first() != Some(&Fr::ONE) {
            return Err(SynthesisError::Unsatisfiable);
        }
        if self
            .r1cs
            .num_public
            .checked_add(1)
            .expect("R1CS num of public inputs addition failed")
            > self.r1cs.num_wires
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let num_public = self.r1cs.num_public as usize;
        let num_wires = self.r1cs.num_wires as usize;

        // Allocate all variables and store them for constraint generation
        let mut variables: Vec<Variable> = Vec::with_capacity(num_wires);

        // Wire 0 is always the constant 1 (already exists as Variable::One in arkworks)
        variables.push(Variable::One);

        // Allocate public inputs (wires 1..=num_public)
        if self.witness.len() < num_wires {
            return Err(SynthesisError::Unsatisfiable);
        }
        for i in 1..=num_public {
            let value = if i < self.witness.len() {
                self.witness[i]
            } else {
                return Err(SynthesisError::Unsatisfiable);
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
        let max_wire = self.r1cs.num_wires as usize;

        // Validate wire IDs once
        for constraint in &self.r1cs.constraints {
            for t in constraint
                .a
                .terms
                .iter()
                .chain(&constraint.b.terms)
                .chain(&constraint.c.terms)
            {
                if (t.wire_id as usize) >= max_wire {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }
        // Enforce constraints without per-constraint allocations
        for constraint in &self.r1cs.constraints {
            cs.enforce_r1cs_constraint(
                || {
                    let mut lc_a = lc!();
                    for t in &constraint.a.terms {
                        lc_a.add_assign((t.coefficient, variables[t.wire_id as usize]));
                    }
                    lc_a
                },
                || {
                    let mut lc_b = lc!();
                    for t in &constraint.b.terms {
                        lc_b.add_assign((t.coefficient, variables[t.wire_id as usize]));
                    }
                    lc_b
                },
                || {
                    let mut lc_c = lc!();
                    for t in &constraint.c.terms {
                        lc_c.add_assign((t.coefficient, variables[t.wire_id as usize]));
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
    /// Uses unchecked deserialization since the proving key is trusted.
    /// Skips curve point validation for faster initialization.
    ///
    /// # Arguments
    /// * `pk_bytes` - Serialized proving key (compressed)
    /// * `r1cs_bytes` - R1CS binary file contents
    #[wasm_bindgen(constructor)]
    pub fn new(pk_bytes: &[u8], r1cs_bytes: &[u8]) -> Result<Prover, JsValue> {
        // Deserialize proving key. Unchecked, proving key is trusted
        let pk = ProvingKey::<Bn254>::deserialize_compressed_unchecked(pk_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to load proving key: {}", e)))?;

        // Extract verifying key from proving key
        let vk = pk.vk.clone();

        // Parse R1CS
        let r1cs = R1CS::parse(r1cs_bytes)?;

        // Check correctness of the extracted verifying key
        if vk.gamma_abc_g1.len().saturating_sub(1) != r1cs.num_public as usize {
            return Err(JsValue::from_str(
                "VK public input count doesn't match R1CS",
            ));
        }

        // Process verifying key for faster verification
        let pvk = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::process_vk(&vk)
            .map_err(|e| JsValue::from_str(&format!("Failed to process VK: {}", e)))?;

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

    /// Generate proof and return as uncompressed bytes ready for Soroban.
    ///
    /// Format: [A (64 bytes) || B (128 bytes) || C (64 bytes)] = 256 bytes
    /// G2 points use Soroban-compatible c1||c0 (imaginary||real) ordering.
    #[wasm_bindgen]
    pub fn prove_bytes_uncompressed(&self, witness_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        // Validate witness size
        if !witness_bytes.len().is_multiple_of(FIELD_SIZE) {
            return Err(JsValue::from_str(&format!(
                "Invalid witness size: {} bytes (not multiple of {})",
                witness_bytes.len(),
                FIELD_SIZE
            )));
        }

        let num_witness_elements = witness_bytes.len() / FIELD_SIZE;

        if num_witness_elements < self.r1cs.num_wires as usize {
            return Err(JsValue::from_str(&format!(
                "Witness too short: {} elements, circuit needs {} wires",
                num_witness_elements, self.r1cs.num_wires
            )));
        }

        let mut witness: Vec<Fr> = Vec::with_capacity(num_witness_elements);
        for chunk in witness_bytes.chunks_exact(FIELD_SIZE) {
            witness.push(bytes_to_fr(chunk)?);
        }

        let circuit = R1CSCircuit {
            r1cs: self.r1cs.clone(),
            witness,
        };

        let mut rng = OsRng;
        let proof = <ark_groth16::Groth16<Bn254> as SNARK<Fr>>::prove(&self.pk, circuit, &mut rng)
            .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;

        Ok(proof_to_uncompressed_bytes(&proof))
    }

    /// Convert compressed proof bytes to uncompressed Soroban format.
    ///
    /// Input: compressed proof [A || B || C]
    /// Output: uncompressed [A (64) || B (128) || C (64)] = 256 bytes
    #[wasm_bindgen]
    pub fn proof_bytes_to_uncompressed(&self, proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| JsValue::from_str(&format!("Failed to load proof: {}", e)))?;
        Ok(proof_to_uncompressed_bytes(&proof))
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

/// Standalone function to convert compressed proof to Soroban format.
///
/// Input: compressed proof [A || B || C]
/// Output: uncompressed [A (64) || B (128) || C (64)] = 256 bytes
/// G2 points use Soroban-compatible c1||c0 ordering.
#[wasm_bindgen]
pub fn convert_proof_to_soroban(proof_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize proof: {}", e)))?;
    Ok(proof_to_uncompressed_bytes(&proof))
}

/// Converts a compressed verifying key to Soroban-compatible uncompressed
/// format.
///
/// Output structure (concatenated bytes):
/// - alpha (64 bytes): G1 point
/// - beta (128 bytes): G2 point (c1||c0 ordering)
/// - gamma (128 bytes): G2 point (c1||c0 ordering)
/// - delta (128 bytes): G2 point (c1||c0 ordering)
/// - ic_count (4 bytes): u32 little-endian count of IC points
/// - ic[0..n] (64 bytes each): G1 points
#[wasm_bindgen]
pub fn convert_vk_to_soroban(vk_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes)
        .map_err(|e| JsValue::from_str(&format!("Failed to deserialize VK: {}", e)))?;

    let ic_count = vk.gamma_abc_g1.len();

    // VK format: alpha(64) + beta(128) + gamma(128) + delta(128) + ic_count(4) +
    // ic(64*n) Fixed header size = 452 bytes
    const HEADER_SIZE: usize = 452;
    let ic_bytes = ic_count
        .checked_mul(64)
        .ok_or_else(|| JsValue::from_str("IC count overflow"))?;
    let total_size = HEADER_SIZE
        .checked_add(ic_bytes)
        .ok_or_else(|| JsValue::from_str("Total size overflow"))?;

    let mut out = Vec::with_capacity(total_size);

    // alpha (G1)
    out.extend_from_slice(&g1_bytes_uncompressed(&vk.alpha_g1));

    // beta, gamma, delta (G2 with c1||c0 ordering)
    out.extend_from_slice(&g2_bytes_uncompressed(&vk.beta_g2));
    out.extend_from_slice(&g2_bytes_uncompressed(&vk.gamma_g2));
    out.extend_from_slice(&g2_bytes_uncompressed(&vk.delta_g2));

    // IC count as u32 LE
    let ic_count_u32 =
        u32::try_from(ic_count).map_err(|_| JsValue::from_str("IC count exceeds u32 max"))?;
    out.extend_from_slice(&ic_count_u32.to_le_bytes());

    // IC points (G1)
    for ic in &vk.gamma_abc_g1 {
        out.extend_from_slice(&g1_bytes_uncompressed(ic));
    }

    Ok(out)
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
