use crate::Field;
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Current selective-disclosure receipt version.
pub const DISCLOSURE_RECEIPT_VERSION: u32 = 1;

/// Initial selective-disclosure circuit entry point.
pub const SELECTIVE_DISCLOSURE_1_CIRCUIT: &str = "selectiveDisclosure_1";

/// Merkle tree depth expected by `selectiveDisclosure_1`.
pub const SELECTIVE_DISCLOSURE_1_LEVELS: u32 = 10;

/// Number of notes disclosed by `selectiveDisclosure_1`.
pub const SELECTIVE_DISCLOSURE_1_N_NOTES: u32 = 1;
/// Compressed Groth16 proof size used by arkworks for BN254 proofs.
pub const COMPRESSED_GROTH16_PROOF_BYTES: usize = 128;

/// Portable receipt proving ownership of one or more disclosed notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureReceipt {
    /// Receipt schema version.
    pub version: u32,
    /// Circuit metadata and verifying-key binding.
    pub circuit: DisclosureCircuitMetadata,
    /// Pool, authority, and protocol context bound into `ext_context_hash`.
    pub context: DisclosureContext,
    /// Named public inputs for the selective disclosure circuit.
    pub public_inputs: DisclosurePublicInputs,
    /// Compressed Groth16 proof encoded as `0x`-prefixed lowercase hex.
    pub proof_compressed_hex: String,
    /// Issuance timestamp string.
    pub issued_at: String,
}

impl DisclosureReceipt {
    /// Validates schema-level invariants before verification.
    /// This does not perform Groth16 verification or root-history checks.
    pub fn validate(&self) -> Result<()> {
        if self.version != DISCLOSURE_RECEIPT_VERSION {
            return Err(anyhow!("Unsupported disclosure receipt version"));
        }
        self.circuit.validate()?;
        self.context.validate()?;
        self.public_inputs.validate(self.circuit.n_notes)?;
        parse_0x_hex_exact(
            "proof_compressed_hex",
            &self.proof_compressed_hex,
            COMPRESSED_GROTH16_PROOF_BYTES,
        )?;

        if self.issued_at.is_empty() {
            return Err(anyhow!("issued_at cannot be empty"));
        }

        Ok(())
    }

    /// Decodes the compressed Groth16 proof bytes carried by this receipt.
    ///
    /// # Returns
    /// Returns the compressed proof encoded in `proof_compressed_hex`.
    ///
    /// # Errors
    /// Returns an error if the proof is not canonical `0x`-prefixed lowercase
    /// hex or does not decode to the expected compressed proof length.
    pub fn proof_compressed_bytes(&self) -> Result<Vec<u8>> {
        parse_0x_hex_exact(
            "proof_compressed_hex",
            &self.proof_compressed_hex,
            COMPRESSED_GROTH16_PROOF_BYTES,
        )
    }
}

/// Circuit identity and verifying-key binding carried by a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureCircuitMetadata {
    /// Circuit entry-point name, e.g. `selectiveDisclosure_1`.
    pub name: String,
    /// Pool Merkle tree depth expected by the circuit.
    pub levels: u32,
    /// Number of note disclosures represented by this circuit instance.
    pub n_notes: u32,
    /// Hash of the verifying key encoded as `0x`-prefixed lowercase 32-byte
    /// hex.
    pub vk_hash: String,
}

impl DisclosureCircuitMetadata {
    /// Validates metadata fields that are independent of any concrete registry.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(anyhow!("Circuit name cannot be empty"));
        }
        if self.levels == 0 {
            return Err(anyhow!("Circuit levels cannot be zero"));
        }
        if self.n_notes == 0 {
            return Err(anyhow!("Circuit n_notes cannot be zero"));
        }
        parse_0x_hex_exact("vk_hash", &self.vk_hash, 32)?;
        Ok(())
    }
}

/// Receipt context that is hashed into `ext_context_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureContext {
    /// Network name from the active deployment configuration.
    pub network: String,
    /// Pool contract address.
    pub pool_address: String,
    /// Human-readable authority label.
    pub authority_label: String,
    /// Authority identity payload encoded as `0x`-prefixed lowercase hex.
    pub authority_identity_payload_hex: String,
    /// Purpose string shown to the user and bound into the receipt context.
    pub purpose: String,
    /// Optional anti-replay nonce encoded as a field element.
    pub context_nonce: Field,
}

impl DisclosureContext {
    /// Validates context metadata before recomputing the context hash.
    pub fn validate(&self) -> Result<()> {
        if self.network.is_empty() {
            return Err(anyhow!("Network cannot be empty"));
        }
        if self.pool_address.is_empty() {
            return Err(anyhow!("pool_address cannot be empty"));
        }
        if self.authority_label.is_empty() {
            return Err(anyhow!("authority_label cannot be empty"));
        }
        parse_0x_hex(
            "authority_identity_payload_hex",
            &self.authority_identity_payload_hex,
        )?;
        if self.purpose.is_empty() {
            return Err(anyhow!("Purpose cannot be empty"));
        }
        Ok(())
    }
}

/// Public inputs exposed by `selectiveDisclosure_1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosurePublicInputs {
    /// Merkle roots proven by the receipt.
    pub roots: Vec<Field>,
    /// Disclosed note commitments proven under `roots`.
    pub note_commitments: Vec<Field>,
    /// Hash of pool, authority, purpose, and nonce context.
    pub ext_context_hash: Field,
}

impl DisclosurePublicInputs {
    /// Validates public-input shape against the circuit's note count.
    pub fn validate(&self, n_notes: u32) -> Result<()> {
        let n_notes = usize::try_from(n_notes).map_err(|_| anyhow!("n_notes out of range"))?;
        if self.roots.len() != n_notes {
            return Err(anyhow!("Roots length does not match n_notes"));
        }
        if self.note_commitments.len() != n_notes {
            return Err(anyhow!("note_commitments length does not match n_notes"));
        }
        Ok(())
    }
}

/// Verification status returned.
///
/// # Security semantics
/// A receipt is trustworthy **only when all three fields are `true`**:
/// `proof_verified && context_verified && known_root_status`. The fields are
/// kept separate so callers can diagnose *why* verification failed, but a
/// consumer must check the conjunction, not any individual flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisclosureVerificationReport {
    /// Whether the Groth16 proof verified against the receipt public inputs.
    pub proof_verified: bool,
    /// Whether the receipt context recomputed to the public `ext_context_hash`.
    pub context_verified: bool,
    /// Status of the known-root freshness check.
    pub known_root_status: bool,
}

impl DisclosureVerificationReport {
    /// Returns `true` only when proof, context, and root freshness all pass.
    pub fn is_fully_verified(&self) -> bool {
        self.proof_verified && self.context_verified && self.known_root_status
    }
}
/// Parses a strict `0x`-prefixed lowercase hex string.
///
/// The receipt format uses this for proof bytes, verifying-key hashes, and
/// context payloads so JSON parsing fails before any verifier logic runs.
/// Uppercase hex and missing prefixes are rejected to keep receipts canonical.
///
/// # Arguments
/// * `name` - Field name used in validation error messages.
/// * `value` - Hex string to parse. It must start with `0x`, use lowercase hex
///   digits, and contain at least one byte.
///
/// # Returns
/// Returns the decoded bytes when the string is canonical.
fn parse_0x_hex(name: &str, value: &str) -> Result<Vec<u8>> {
    let Some(hex_value) = value.strip_prefix("0x") else {
        return Err(anyhow!("{name}: expected 0x prefix"));
    };
    if hex_value.is_empty() {
        return Err(anyhow!("{name}: hex payload cannot be empty"));
    }
    if !hex_value.len().is_multiple_of(2) {
        return Err(anyhow!("{name}: hex payload must have even length"));
    }
    if hex_value.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(anyhow!("{name}: expected lowercase hex"));
    }

    hex::decode(hex_value).map_err(|e| anyhow!("{name}: invalid hex: {e}"))
}

/// Parses a strict hex string and checks the decoded byte length.
///
/// # Arguments
/// * `name` - Field name used in validation error messages.
/// * `value` - Hex string to parse.
/// * `expected_bytes` - Required decoded byte length.
///
/// # Returns
/// Returns the decoded bytes when the string is canonical and has the expected
/// length.
fn parse_0x_hex_exact(name: &str, value: &str, expected_bytes: usize) -> Result<Vec<u8>> {
    let bytes = parse_0x_hex(name, value)?;
    if bytes.len() != expected_bytes {
        return Err(anyhow!(
            "{name}: expected {} bytes, got {}",
            expected_bytes,
            bytes.len()
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: u64) -> Field {
        Field(crate::U256::from(value))
    }

    fn valid_receipt() -> DisclosureReceipt {
        DisclosureReceipt {
            version: DISCLOSURE_RECEIPT_VERSION,
            circuit: DisclosureCircuitMetadata {
                name: SELECTIVE_DISCLOSURE_1_CIRCUIT.to_string(),
                levels: SELECTIVE_DISCLOSURE_1_LEVELS,
                n_notes: SELECTIVE_DISCLOSURE_1_N_NOTES,
                vk_hash: format!("0x{}", "11".repeat(32)),
            },
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
            proof_compressed_hex: format!("0x{}", "aa".repeat(COMPRESSED_GROTH16_PROOF_BYTES)),
            issued_at: "2026-05-19T14:00:00Z".to_string(),
        }
    }

    #[test]
    fn receipt_round_trips_and_validates() -> Result<()> {
        let receipt = valid_receipt();
        let json = serde_json::to_string(&receipt)?;
        let parsed: DisclosureReceipt = serde_json::from_str(&json)?;

        assert_eq!(parsed, receipt);
        parsed.validate()?;

        Ok(())
    }

    #[test]
    fn receipt_rejects_unknown_fields() {
        let json = r#"{
            "version": 1,
            "unexpected": true,
            "circuit": {"name": "selectiveDisclosure_1", "levels": 10, "nNotes": 1, "vkHash": "0x1111111111111111111111111111111111111111111111111111111111111111"},
            "context": {"network": "testnet", "poolAddress": "CAAA", "authorityLabel": "A", "authorityIdentityPayloadHex": "0x61", "purpose": "p", "contextNonce": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "publicInputs": {"roots": [], "noteCommitments": [], "extContextHash": "0x0000000000000000000000000000000000000000000000000000000000000000"},
            "proofCompressedHex": "0x",
            "issuedAt": "now"
        }"#;

        assert!(serde_json::from_str::<DisclosureReceipt>(json).is_err());
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut receipt = valid_receipt();
        receipt.version = 2;

        assert!(receipt.validate().is_err());
    }

    #[test]
    fn validate_rejects_malformed_proof_hex() {
        let mut receipt = valid_receipt();
        receipt.proof_compressed_hex = "0xaa".to_string();

        assert!(receipt.validate().is_err());
    }

    #[test]
    fn validate_rejects_missing_hex_prefix() {
        let mut receipt = valid_receipt();
        receipt.circuit.vk_hash = "11".repeat(32);

        assert!(receipt.validate().is_err());
    }

    #[test]
    fn validate_rejects_uppercase_hex() {
        let mut receipt = valid_receipt();
        receipt.context.authority_identity_payload_hex = "0xAA".to_string();

        assert!(receipt.validate().is_err());
    }

    #[test]
    fn validate_rejects_public_input_count_mismatch() {
        let mut receipt = valid_receipt();
        receipt.public_inputs.note_commitments.push(field(4));

        assert!(receipt.validate().is_err());
    }
}
