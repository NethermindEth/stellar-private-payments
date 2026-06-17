//! Selective-disclosure circuit metadata and receipt validation.

use anyhow::{Result, anyhow};
use prover::prover::{Prover, verify_proof};
use sha2::{Digest, Sha256};
use types::{
    DisclosureCircuitMetadata, DisclosureContext, DisclosureReceipt, DisclosureVerificationReport,
    Field, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_1_LEVELS,
    SELECTIVE_DISCLOSURE_1_N_NOTES,
};

/// Domain prefix for `ext_context_hash` derivation.
const CONTEXT_HASH_DOMAIN: &[u8] = b"disclosure-context-v1";

/// Compute the canonical `vk_hash` string from verifying-key bytes.
///
/// The hash is SHA-256 over the compressed VK bytes, formatted as a
/// `0x`-prefixed lowercase hex string. Both the prover and verifier must
/// use this exact function to stay in sync.
pub fn vk_hash_hex(vk_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk_bytes);
    let digest = hasher.finalize();
    format!("0x{}", hex::encode(digest))
}

/// Derives the `ext_context_hash` from disclosure context fields.
///
/// The derivation is deterministic and uses SHA-256 over a canonical,
/// length-delimited encoding of all context fields, reduced modulo the BN254
/// prime. Both the prover and verifier must use this exact function to stay
/// in sync.
///
/// # Arguments
/// * `context` - Disclosure context containing network, pool address,
///   authority, purpose, and nonce.
///
/// # Returns
/// Returns the derived field element.
///
/// # Errors
/// Returns an error if context validation fails.
pub fn derive_ext_context_hash(context: &DisclosureContext) -> Result<Field> {
    context.validate()?;

    let mut hasher = Sha256::new();
    hasher.update(CONTEXT_HASH_DOMAIN);

    // Helper to feed a string with its exact length prefix (little-endian u64).
    let mut feed_str = |s: &str| {
        hasher.update((s.len() as u64).to_le_bytes());
        hasher.update(s.as_bytes());
    };

    feed_str(&context.network);
    feed_str(&context.pool_address);
    feed_str(&context.authority_label);
    feed_str(&context.authority_identity_payload_hex);
    feed_str(&context.purpose);
    hasher.update(context.context_nonce.to_le_bytes());

    let hash: [u8; 32] = hasher.finalize().into();
    Ok(Field::from_le_bytes_mod_order(hash))
}

/// Verifies that a receipt's `ext_context_hash` is internally consistent with
/// its declared [`DisclosureContext`].
///
/// # Arguments
/// * `receipt` - Receipt to verify.
///
/// # Returns
/// Returns `true` when the re-derived hash matches the stored public input.
///
/// # Errors
/// Returns an error if the receipt context is invalid.
pub fn verify_receipt_context(receipt: &DisclosureReceipt) -> Result<bool> {
    let expected = derive_ext_context_hash(&receipt.context)?;
    Ok(expected == receipt.public_inputs.ext_context_hash)
}

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
    levels: SELECTIVE_DISCLOSURE_1_LEVELS,
    n_notes: SELECTIVE_DISCLOSURE_1_N_NOTES,
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
    prove_receipt_proof_with_prover(&prover, witness_bytes)
}

/// Proves a disclosure witness using an existing Groth16 prover.
///
/// This is identical to [`prove_receipt_proof`] but reuses an already
/// initialised [`Prover`] instance, avoiding the cost of re-deserialising
/// the proving key and R1CS for each request.
///
/// # Arguments
/// * `prover` - Initialised Groth16 prover holding the disclosure circuit
///   proving key and R1CS.
/// * `witness_bytes` - Witness bytes produced by the circuit witness
///   calculator.
///
/// # Returns
/// Returns the compressed proof bytes and extracted public inputs.
///
/// # Errors
/// Returns an error if proving fails, public input extraction fails, or the
/// generated proof does not verify locally.
pub fn prove_receipt_proof_with_prover(
    prover: &Prover,
    witness_bytes: &[u8],
) -> Result<ProvedReceiptProof> {
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

/// Checks that every receipt root is still known by the pool.
///
/// # Arguments
/// * `receipt` - Receipt containing roots to check.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
/// * `is_known_root` - Root freshness predicate (for example, a contract call).
///
/// # Returns
/// Returns `true` when all roots in the receipt are known.
///
/// # Errors
/// Returns an error if receipt metadata is invalid or if `is_known_root`
/// fails for any root.
pub fn verify_receipt_known_roots_with<F>(
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
    mut is_known_root: F,
) -> Result<bool>
where
    F: FnMut(Field) -> Result<bool>,
{
    validate_registered_receipt(receipt, expected_vk_hash)?;
    for root in &receipt.public_inputs.roots {
        if !is_known_root(*root)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Builds a disclosure verification report by combining proof and root checks.
///
/// # Arguments
/// * `receipt` - Disclosure receipt to verify.
/// * `expected_vk_hash` - Verifying-key hash expected by the caller.
/// * `verify_proof` - Proof-verification function.
/// * `context_verified` - Result of context-hash verification.
/// * `is_known_root` - Root freshness predicate.
///
/// # Returns
/// Returns a report that keeps proof-validity and root-freshness status
/// separate.
///
/// # Errors
/// Returns an error if receipt metadata is invalid or if callbacks fail.
pub fn verify_receipt_report_with<P, R>(
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
    mut verify_proof: P,
    context_verified: bool,
    mut is_known_root: R,
) -> Result<DisclosureVerificationReport>
where
    P: FnMut(&DisclosureReceipt, &str) -> Result<bool>,
    R: FnMut(Field) -> Result<bool>,
{
    validate_registered_receipt(receipt, expected_vk_hash)?;

    let proof_verified = verify_proof(receipt, expected_vk_hash)?;
    let known_root_status =
        verify_receipt_known_roots_with(receipt, expected_vk_hash, &mut is_known_root)?;

    Ok(DisclosureVerificationReport {
        proof_verified,
        context_verified,
        known_root_status,
    })
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

    #[test]
    fn known_roots_returns_false_when_root_is_stale() -> Result<()> {
        let receipt = valid_receipt();
        let known = verify_receipt_known_roots_with(&receipt, VK_HASH, |_root| Ok(false))?;
        assert!(!known);
        Ok(())
    }

    #[test]
    fn verification_report_distinguishes_proof_from_root_freshness() -> Result<()> {
        let receipt = valid_receipt();

        // Shape validation succeeds and the injected proof checker says the
        // proof is valid, but root freshness fails.
        let report = verify_receipt_report_with(
            &receipt,
            VK_HASH,
            |r, _vk_hash| {
                r.proof_compressed_bytes()?;
                Ok(true)
            },
            true,
            |_root| Ok(false),
        )?;

        assert!(report.proof_verified);
        assert!(report.context_verified);
        assert!(!report.known_root_status);
        Ok(())
    }

    #[test]
    fn verification_report_short_circuits_on_invalid_metadata() {
        let mut receipt = valid_receipt();
        receipt.circuit.levels = 11;

        let mut proof_called = false;
        let mut root_called = false;

        let result = verify_receipt_report_with(
            &receipt,
            VK_HASH,
            |_r, _vk_hash| {
                proof_called = true;
                Ok(true)
            },
            true,
            |_root| {
                root_called = true;
                Ok(true)
            },
        );

        assert!(result.is_err());
        assert!(!proof_called);
        assert!(!root_called);
    }

    #[test]
    fn known_roots_returns_true_when_all_roots_are_known() -> Result<()> {
        let receipt = valid_receipt();
        let known = verify_receipt_known_roots_with(&receipt, VK_HASH, |_root| Ok(true))?;
        assert!(known);
        Ok(())
    }

    #[test]
    fn verification_report_all_checks_pass() -> Result<()> {
        let receipt = valid_receipt();

        let report = verify_receipt_report_with(
            &receipt,
            VK_HASH,
            |r, _vk_hash| {
                r.proof_compressed_bytes()?;
                Ok(true)
            },
            true,
            |_root| Ok(true),
        )?;

        assert!(report.proof_verified);
        assert!(report.context_verified);
        assert!(report.known_root_status);
        Ok(())
    }

    #[test]
    fn derive_ext_context_hash_is_deterministic() -> Result<()> {
        let ctx = valid_receipt().context;
        let a = derive_ext_context_hash(&ctx)?;
        let b = derive_ext_context_hash(&ctx)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn derive_ext_context_hash_is_sensitive_to_every_field() -> Result<()> {
        let base = valid_receipt().context;
        let base_hash = derive_ext_context_hash(&base)?;

        let mut mutated = base.clone();
        mutated.network = "mainnet".to_string();
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        mutated = base.clone();
        mutated.pool_address =
            "CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string();
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        mutated = base.clone();
        mutated.authority_label = "Authority ABC".to_string();
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        mutated = base.clone();
        mutated.authority_identity_payload_hex = "0xdeadbeef".to_string();
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        mutated = base.clone();
        mutated.purpose = "aml-check".to_string();
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        mutated = base.clone();
        mutated.context_nonce = field(99);
        assert_ne!(derive_ext_context_hash(&mutated)?, base_hash);

        Ok(())
    }

    #[test]
    fn verify_receipt_context_succeeds_when_hash_matches() -> Result<()> {
        let mut receipt = valid_receipt();
        let expected = derive_ext_context_hash(&receipt.context)?;
        receipt.public_inputs.ext_context_hash = expected;
        assert!(verify_receipt_context(&receipt)?);
        Ok(())
    }

    #[test]
    fn verify_receipt_context_fails_when_hash_mismatches() -> Result<()> {
        let receipt = valid_receipt();
        assert!(!verify_receipt_context(&receipt)?);
        Ok(())
    }

    #[test]
    fn derive_ext_context_hash_rejects_invalid_context() {
        let mut ctx = valid_receipt().context;
        ctx.network = "".to_string();
        assert!(derive_ext_context_hash(&ctx).is_err());
    }

    #[test]
    fn vk_hash_hex_is_deterministic() {
        let a = vk_hash_hex(&[1u8, 2, 3]);
        let b = vk_hash_hex(&[1u8, 2, 3]);
        assert_eq!(a, b);
    }

    #[test]
    fn vk_hash_hex_is_sensitive_to_input() {
        let a = vk_hash_hex(&[1u8, 2, 3]);
        let b = vk_hash_hex(&[1u8, 2, 4]);
        assert_ne!(a, b);
    }

    #[test]
    fn vk_hash_hex_format_is_valid() {
        let h = vk_hash_hex(&[0u8; 32]);
        assert!(h.starts_with("0x"));
        assert_eq!(h.len(), 66); // 0x + 64 hex chars
        assert!(h.chars().skip(2).all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_receipt_proof_rejects_mismatched_vk_hash_before_receipt_validation() {
        // Corrupt the receipt so that metadata validation would fail if it were
        // reached first. The VK-hash guard must fire before receipt validation.
        let mut receipt = valid_receipt();
        receipt.circuit.levels = 11;

        let vk_bytes = [1u8, 2, 3];
        let expected_vk_hash = VK_HASH;

        let err = verify_receipt_proof(&receipt, &vk_bytes, expected_vk_hash)
            .expect_err("mismatched vk_bytes should fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Verifying key hash mismatch"),
            "expected verifying key hash mismatch error, got: {msg}"
        );
        assert!(
            !msg.contains("circuit metadata mismatch"),
            "VK-hash guard should run before receipt metadata validation: {msg}"
        );
    }

    #[test]
    fn verify_receipt_proof_delegates_to_underlying_verifier_when_hash_matches() {
        let mut receipt = valid_receipt();
        let vk_bytes = [1u8, 2, 3];
        let expected_vk_hash = vk_hash_hex(&vk_bytes);

        // Align the receipt metadata with the expected hash so that the
        // metadata check passes and we reach the underlying verifier.
        receipt.circuit.vk_hash = expected_vk_hash.clone();

        // The VK hash matches, so the function proceeds to public-input
        // serialization and then to the underlying verify_proof. The dummy
        // vk_bytes are not a valid compressed verifying key, so the error must
        // come from the verifier, not from the VK-hash guard.
        let err = verify_receipt_proof(&receipt, &vk_bytes, &expected_vk_hash)
            .expect_err("dummy vk_bytes should fail proof verification");
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("Verifying key hash mismatch"),
            "matching hash should not trigger verifying key hash mismatch: {msg}"
        );
        assert!(
            msg.contains("Failed to load VK") || msg.contains("Failed to load proof"),
            "expected underlying verifier error, got: {msg}"
        );
    }
}
