//! Selective-disclosure circuit metadata and receipt validation.

use anyhow::{Result, anyhow};
use prover::prover::{Prover, verify_proof};
use sha2::{Digest, Sha256};
use types::{DisclosureCircuitMetadata, DisclosureReceipt, SELECTIVE_DISCLOSURE_1_CIRCUIT};

/// Public input order declared by `selectiveDisclosure_1.circom`.
pub const SELECTIVE_DISCLOSURE_1_PUBLIC_INPUTS_ORDER: &[&str] =
    &["roots", "noteCommitments", "extContextHash"];

/// Artifact file names for a registered disclosure circuit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CircuitArtifacts {
    /// Circuit WASM file name.
    pub wasm: &'static str,
    /// Circuit R1CS file name.
    pub r1cs: &'static str,
    /// Groth16 proving-key file name.
    pub proving_key: &'static str,
    /// Groth16 verifying-key JSON file name.
    pub verifying_key_json: &'static str,
}

/// Static metadata for a registered disclosure circuit.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RegisteredCircuit {
    /// Circuit entry-point name.
    pub name: &'static str,
    /// Merkle tree depth expected by the circuit.
    pub levels: u32,
    /// Number of note disclosures represented by the circuit.
    pub n_notes: u32,
    /// Public input order used by the witness and verifier.
    pub public_inputs_order: &'static [&'static str],
    /// Artifact file names used by build, web, and CLI callers.
    pub artifacts: CircuitArtifacts,
}

impl RegisteredCircuit {
    /// Builds the receipt metadata expected for this circuit and verifying key.
    ///
    /// # Arguments
    /// * `vk_hash` - Hash of the verifying key encoded as `0x`-prefixed
    ///   lowercase hex.
    ///
    /// # Returns
    /// Returns circuit metadata suitable for a disclosure receipt.
    pub fn receipt_metadata(&self, vk_hash: &str) -> DisclosureCircuitMetadata {
        DisclosureCircuitMetadata {
            name: self.name.to_string(),
            levels: self.levels,
            n_notes: self.n_notes,
            vk_hash: vk_hash.to_string(),
        }
    }

    /// Validates a receipt against this registered circuit.
    ///
    /// # Arguments
    /// * `receipt` - Receipt to validate.
    /// * `expected_vk_hash` - Verifying-key hash expected by the caller.
    ///
    /// # Returns
    /// Returns `Ok(())` when the receipt schema, circuit metadata, and public
    /// input shape match this circuit.
    ///
    /// # Errors
    /// Returns an error if the receipt schema is invalid, the circuit metadata
    /// does not match this circuit, or the verifying-key hash differs from
    /// `expected_vk_hash`.
    pub fn validate_receipt(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<()> {
        receipt.validate()?;

        let expected = self.receipt_metadata(expected_vk_hash);
        expected.validate()?;

        if receipt.circuit != expected {
            return Err(anyhow!("Disclosure receipt circuit metadata mismatch"));
        }

        Ok(())
    }

    /// Serializes receipt public inputs in `public_inputs_order`.
    ///
    /// The caller must already have validated `receipt` against this circuit
    /// (via [`validate_registered_receipt`] or
    /// [`RegisteredCircuit::validate_receipt`]).
    ///
    /// # Arguments
    /// * `receipt` - Receipt whose public inputs are serialized.
    ///
    /// # Returns
    /// Returns public inputs as 32-byte little-endian field elements, suitable
    /// for the generic Groth16 verifier.
    ///
    /// # Errors
    /// Returns an error if `public_inputs_order` contains an unknown name or if
    /// the output buffer capacity overflows.
    pub fn public_inputs_bytes(&self, receipt: &DisclosureReceipt) -> Result<Vec<u8>> {
        let n_notes =
            usize::try_from(self.n_notes).map_err(|_| anyhow!("Circuit n_notes out of range"))?;
        let capacity = n_notes
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_mul(32))
            .ok_or_else(|| anyhow!("Public input byte capacity overflow"))?;
        let mut out = Vec::with_capacity(capacity);

        for &name in self.public_inputs_order {
            match name {
                "roots" => {
                    for root in &receipt.public_inputs.roots {
                        out.extend_from_slice(&root.to_le_bytes());
                    }
                }
                "noteCommitments" => {
                    for note_commitment in &receipt.public_inputs.note_commitments {
                        out.extend_from_slice(&note_commitment.to_le_bytes());
                    }
                }
                "extContextHash" => {
                    out.extend_from_slice(&receipt.public_inputs.ext_context_hash.to_le_bytes());
                }
                other => {
                    return Err(anyhow!(
                        "Unknown public input `{other}` in circuit `{}` order",
                        self.name
                    ));
                }
            }
        }

        Ok(out)
    }
}

/// Hashes serialized verifying-key bytes using the receipt VK hash format.
///
/// # Arguments
/// * `vk_bytes` - Serialized compressed arkworks verifying key.
///
/// # Returns
/// Returns the `0x`-prefixed lowercase SHA-256 hash used in disclosure
/// receipts.
pub fn verifying_key_hash(vk_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk_bytes);
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Validates that serialized verifying-key bytes match an expected VK hash.
///
/// # Arguments
/// * `vk_bytes` - Serialized compressed arkworks verifying key.
/// * `expected_vk_hash` - Expected `0x`-prefixed lowercase SHA-256 hash.
///
/// # Returns
/// Returns `Ok(())` when `vk_bytes` hash to `expected_vk_hash`.
///
/// # Errors
/// Returns an error when the actual verifying-key hash differs from
/// `expected_vk_hash`.
fn validate_verifying_key_hash(vk_bytes: &[u8], expected_vk_hash: &str) -> Result<bool> {
    let actual_vk_hash = verifying_key_hash(vk_bytes);

    if actual_vk_hash != expected_vk_hash {
        return Err(anyhow!("Verifying key hash mismatch"));
    }

    Ok(true)
}

/// Circuit metadata for `selectiveDisclosure_1`.
pub const SELECTIVE_DISCLOSURE_1: RegisteredCircuit = RegisteredCircuit {
    name: SELECTIVE_DISCLOSURE_1_CIRCUIT,
    levels: 10,
    n_notes: 1,
    public_inputs_order: SELECTIVE_DISCLOSURE_1_PUBLIC_INPUTS_ORDER,
    artifacts: CircuitArtifacts {
        wasm: "selectiveDisclosure_1.wasm",
        r1cs: "selectiveDisclosure_1.r1cs",
        proving_key: "selectiveDisclosure_1_proving_key.bin",
        verifying_key_json: "selectiveDisclosure_1_vk.json",
    },
};

/// Finds a registered disclosure circuit by entry-point name.
///
/// # Arguments
/// * `name` - Circuit entry-point name from a receipt.
///
/// # Returns
/// Returns the registered circuit when `name` is known.
pub fn find_circuit(name: &str) -> Option<&'static RegisteredCircuit> {
    match name {
        SELECTIVE_DISCLOSURE_1_CIRCUIT => Some(&SELECTIVE_DISCLOSURE_1),
        _ => None,
    }
}

/// Validates a receipt against the registered circuit named in the receipt.
///
/// # Arguments
/// * `receipt` - Receipt to validate.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
///
/// # Returns
/// Returns the registered circuit when the receipt validates successfully.
///
/// # Errors
/// Returns an error if the receipt names an unknown circuit, fails schema
/// validation, or does not match the expected circuit metadata.
pub fn validate_registered_receipt(
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
) -> Result<&'static RegisteredCircuit> {
    let circuit = find_circuit(&receipt.circuit.name)
        .ok_or_else(|| anyhow!("Unknown disclosure circuit: {}", receipt.circuit.name))?;
    circuit.validate_receipt(receipt, expected_vk_hash)?;
    Ok(circuit)
}

/// Mock-checks every root named by a disclosure receipt.
///
/// # Arguments
/// * `receipt` - Receipt containing the roots to check.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
///
/// # Returns
/// Returns `true` after receipt metadata validation.
///
/// # Errors
/// Returns an error if receipt metadata is invalid.
/// TODO: REMOVE THIS AFTER MODIFYING THE SMART CONTRACT.
pub fn mock_receipt_roots_are_known(
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
) -> Result<bool> {
    validate_registered_receipt(receipt, expected_vk_hash)?;
    Ok(true)
}

/// Proof bytes and public inputs produced for a disclosure receipt.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProvedReceiptProof {
    /// Compressed arkworks proof bytes.
    pub proof_compressed: Vec<u8>,
    /// Public inputs extracted from the witness in circuit order.
    pub public_inputs: Vec<u8>,
}

/// Proves a disclosure witness using the real Groth16 prover.
///
/// # Arguments
/// * `proving_key_bytes` - Serialized compressed Groth16 proving key.
/// * `r1cs_bytes` - R1CS bytes for the disclosure circuit.
/// * `witness_bytes` - Witness bytes produced by the circuit witness
///   calculator.
///
/// # Returns
/// Returns the compressed proof bytes and extracted public inputs.
///
/// # Errors
/// Returns an error if the proving key or R1CS cannot be loaded, proving
/// fails, public input extraction fails, or the generated proof does not verify
/// locally.
pub fn prove_receipt_proof(
    proving_key_bytes: &[u8],
    r1cs_bytes: &[u8],
    witness_bytes: &[u8],
) -> Result<ProvedReceiptProof> {
    let prover = Prover::new(proving_key_bytes, r1cs_bytes)?;
    let proof_compressed = prover.prove_bytes(witness_bytes)?;
    let public_inputs = prover.extract_public_inputs(witness_bytes)?;

    if !prover.verify(&proof_compressed, &public_inputs)? {
        return Err(anyhow!("Generated disclosure proof did not verify"));
    }

    Ok(ProvedReceiptProof {
        proof_compressed,
        public_inputs,
    })
}

/// Validates a receipt, then serializes its public inputs for Groth16
/// verification.
///
/// This is a convenience wrapper for callers that have not already validated
/// the receipt. It checks the receipt against the registered circuit and
/// `expected_vk_hash` before serializing public inputs.
///
/// Prefer [`validate_registered_receipt`] plus
/// [`RegisteredCircuit::public_inputs_bytes`] when the receipt is already
/// validated in the same call path.
///
/// # Arguments
/// * `receipt` - Receipt containing named public inputs.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
///
/// # Returns
/// Returns public inputs as 32-byte little-endian field elements, suitable for
/// the generic Groth16 verifier.
///
/// # Errors
/// Returns an error if receipt validation fails, the receipt does not match a
/// registered circuit, or public-input serialization fails.
pub fn validate_and_serialize_receipt_public_inputs(
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
) -> Result<Vec<u8>> {
    let circuit = validate_registered_receipt(receipt, expected_vk_hash)?;
    circuit.public_inputs_bytes(receipt)
}

/// Verifies the Groth16 proof carried by a disclosure receipt.
///
/// # Arguments
/// * `receipt` - Receipt containing proof bytes and named public inputs.
/// * `vk_bytes` - Serialized compressed arkworks verifying key.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
///
/// # Returns
/// Returns `true` when the receipt proof verifies against `vk_bytes` and the
/// receipt public inputs.
///
/// # Errors
/// Returns an error if `vk_bytes` do not match `expected_vk_hash`, the receipt
/// is malformed, targets an unsupported circuit, has unexpected metadata, or
/// contains malformed proof bytes.
pub fn verify_receipt_proof(
    receipt: &DisclosureReceipt,
    vk_bytes: &[u8],
    expected_vk_hash: &str,
) -> Result<bool> {
    validate_verifying_key_hash(vk_bytes, expected_vk_hash)?;

    let circuit = validate_registered_receipt(receipt, expected_vk_hash)?;
    let proof_bytes = receipt.proof_compressed_bytes()?;
    let public_inputs = circuit.public_inputs_bytes(receipt)?;
    verify_proof(vk_bytes, &proof_bytes, &public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        DISCLOSURE_RECEIPT_VERSION, DisclosureContext, DisclosurePublicInputs, Field, U256,
    };

    const VK_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

    fn field(value: u64) -> Field {
        Field(U256::from(value))
    }

    fn valid_receipt() -> DisclosureReceipt {
        DisclosureReceipt {
            version: DISCLOSURE_RECEIPT_VERSION,
            circuit: SELECTIVE_DISCLOSURE_1.receipt_metadata(VK_HASH),
            context: DisclosureContext {
                network: "testnet".to_string(),
                pool_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
                authority_label: "Authority XYZ".to_string(),
                authority_identity_payload_hex: "0x617574686f72697479".to_string(),
                purpose: "kyc-review".to_string(),
                context_nonce: field(7),
            },
            public_inputs: DisclosurePublicInputs {
                roots: vec![field(1)],
                note_commitments: vec![field(2)],
                ext_context_hash: field(3),
            },
            proof_compressed_hex: format!("0x{}", "aa".repeat(128)),
            issued_at: "2026-05-19T14:00:00Z".to_string(),
        }
    }

    #[test]
    fn registry_finds_selective_disclosure_1() {
        let circuit = find_circuit(SELECTIVE_DISCLOSURE_1_CIRCUIT)
            .expect("selectiveDisclosure_1 should be registered");

        assert_eq!(circuit, &SELECTIVE_DISCLOSURE_1);
        assert_eq!(
            circuit.public_inputs_order,
            ["roots", "noteCommitments", "extContextHash"]
        );
    }

    #[test]
    fn registry_rejects_unknown_circuit() {
        assert!(find_circuit("unknown").is_none());
    }

    #[test]
    fn validates_registered_receipt() -> Result<()> {
        let receipt = valid_receipt();
        let circuit = validate_registered_receipt(&receipt, VK_HASH)?;

        assert_eq!(circuit.name, SELECTIVE_DISCLOSURE_1_CIRCUIT);
        Ok(())
    }

    #[test]
    fn rejects_wrong_vk_hash() {
        let receipt = valid_receipt();
        let wrong_hash = "0x2222222222222222222222222222222222222222222222222222222222222222";

        assert!(validate_registered_receipt(&receipt, wrong_hash).is_err());
    }

    #[test]
    fn hashes_verifying_key_bytes() {
        let vk_bytes = b"verifying key bytes";

        assert_eq!(
            verifying_key_hash(vk_bytes),
            "0x7330601fe3493c2be3f5ebbca5fc7879af6d7b102016e37d81f12ad40d316fd0"
        );
    }

    #[test]
    fn rejects_verifying_key_hash_mismatch() {
        let expected_vk_hash = verifying_key_hash(b"trusted verifying key bytes");

        assert!(
            validate_verifying_key_hash(b"other verifying key bytes", &expected_vk_hash).is_err()
        );
    }

    #[test]
    fn rejects_wrong_circuit_levels() {
        let mut receipt = valid_receipt();
        receipt.circuit.levels = 11;

        assert!(validate_registered_receipt(&receipt, VK_HASH).is_err());
    }

    #[test]
    fn serializes_public_inputs_in_circuit_order() -> Result<()> {
        let receipt = valid_receipt();
        let circuit = validate_registered_receipt(&receipt, VK_HASH)?;
        let bytes = circuit.public_inputs_bytes(&receipt)?;

        assert_eq!(bytes.len(), 96);
        assert_eq!(&bytes[..32], &field(1).to_le_bytes());
        assert_eq!(&bytes[32..64], &field(2).to_le_bytes());
        assert_eq!(&bytes[64..], &field(3).to_le_bytes());
        Ok(())
    }

    #[test]
    fn validate_and_serialize_matches_circuit_serialization() -> Result<()> {
        let receipt = valid_receipt();
        let circuit = validate_registered_receipt(&receipt, VK_HASH)?;
        let direct = circuit.public_inputs_bytes(&receipt)?;
        let wrapped = validate_and_serialize_receipt_public_inputs(&receipt, VK_HASH)?;

        assert_eq!(direct, wrapped);
        Ok(())
    }

    #[test]
    fn public_input_serialization_rejects_wrong_vk_hash() {
        let receipt = valid_receipt();
        let wrong_hash = "0x2222222222222222222222222222222222222222222222222222222222222222";

        assert!(validate_and_serialize_receipt_public_inputs(&receipt, wrong_hash).is_err());
    }
}
