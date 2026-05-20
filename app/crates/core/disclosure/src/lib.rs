//! Selective-disclosure circuit metadata and receipt validation.
//!
//! This crate intentionally does not perform proving or Groth16 verification
//! yet. It owns the circuit-specific receipt checks that sit above the generic
//! `prover` crate and below the platforms entry points.

use anyhow::{Result, anyhow};
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
            proof_uncompressed_hex: format!("0x{}", "aa".repeat(256)),
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
    fn rejects_wrong_circuit_levels() {
        let mut receipt = valid_receipt();
        receipt.circuit.levels = 11;

        assert!(validate_registered_receipt(&receipt, VK_HASH).is_err());
    }
}
