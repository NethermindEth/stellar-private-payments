//! Selective-disclosure witness building and verification helpers.

use anyhow::Context;

pub use crate::{
    types::DisclosureContext,
    zk::disclosure::{
        RegisteredCircuit, SELECTIVE_DISCLOSURE_1, SELECTIVE_DISCLOSURE_2, SELECTIVE_DISCLOSURE_3,
        SELECTIVE_DISCLOSURE_4, current_issued_at, derive_ext_context_hash, find_circuit,
        find_circuit_by_notes, prove_receipt_proof, prove_receipt_proof_with_prover,
        validate_registered_receipt, verify_receipt_proof, vk_hash_hex,
    },
};

use crate::{
    state::SqliteStorage,
    types::{
        AspMembershipSync, DisclosureReceipt, DisclosureVerificationReport, Field, NoteAmount,
        NotePrivateKey,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    chain::StateFetcher,
    error::Error,
    prover::ProverHandle,
    transact::{build_validated_pool_tree, load_user_key_material},
    zk::merkle::MerkleProof,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureRequest {
    pub selected_commitments: Vec<Field>,
    pub authority_label: String,
    pub authority_identity_payload_hex: String,
    pub purpose: String,
    pub context_nonce: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureInputsRequest {
    pub user_address: String,
    pub kdf_domain: String,
    pub pool_address: String,
    pub selected_commitments: Vec<Field>,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub tree_depth: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureInputs {
    pub root: Field,
    pub note_commitment: Field,
    pub note_amount: NoteAmount,
    pub note_private_key: NotePrivateKey,
    pub note_blinding: Field,
    pub merkle_path_indices: Field,
    pub merkle_path_elements: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureProveParams {
    pub notes: Vec<DisclosureInputs>,
    pub context: DisclosureContext,
}

pub enum BuildDisclosureInputs {
    Ready(Vec<DisclosureInputs>),
    MembershipSync(AspMembershipSync),
}

pub fn build_disclosure_inputs(
    storage: &SqliteStorage,
    req: &DisclosureInputsRequest,
) -> anyhow::Result<BuildDisclosureInputs> {
    if req.selected_commitments.is_empty() || req.selected_commitments.len() > 4 {
        return Err(anyhow::anyhow!(
            "selective disclosure requires 1..=4 selected commitments"
        ));
    }

    let pool_root = req
        .pool_root
        .ok_or_else(|| anyhow::anyhow!("missing pool_root"))?;

    let (note_privkey, _note_pubkey, _encryption_pubkey, _membership_blinding) =
        load_user_key_material(storage, &req.user_address, &req.kdf_domain)?;

    let tree = match build_validated_pool_tree(
        storage,
        &req.pool_address,
        req.pool_next_index,
        req.tree_depth,
        pool_root,
    )? {
        Ok(tree) => tree,
        Err(status) => return Ok(BuildDisclosureInputs::MembershipSync(status)),
    };

    let mut notes = Vec::with_capacity(req.selected_commitments.len());
    for commitment in &req.selected_commitments {
        let (amount, blinding, leaf_index) = storage
            .get_user_note_by_commitment(
                &req.pool_address,
                &req.user_address,
                &req.kdf_domain,
                commitment,
            )?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "note not found for commitment {commitment} in pool {}",
                    req.pool_address
                )
            })?;

        let MerkleProof {
            path_elements,
            path_indices,
            root,
            ..
        } = tree.proof(leaf_index)?;

        notes.push(DisclosureInputs {
            root,
            note_commitment: *commitment,
            note_amount: amount,
            note_private_key: note_privkey.clone(),
            note_blinding: blinding,
            merkle_path_indices: path_indices,
            merkle_path_elements: path_elements,
        });
    }

    Ok(BuildDisclosureInputs::Ready(notes))
}

pub(crate) fn map_build_disclosure_inputs(
    result: anyhow::Result<BuildDisclosureInputs>,
) -> Result<Vec<DisclosureInputs>, Error> {
    match result? {
        BuildDisclosureInputs::Ready(inputs) => Ok(inputs),
        BuildDisclosureInputs::MembershipSync(status) => Err(Error::MembershipSync(status)),
    }
}

fn validate_receipt_context(
    receipt: &DisclosureReceipt,
    expected_network: &str,
    expected_pool: Option<&str>,
    expected_authority: Option<&str>,
) -> Result<(), Error> {
    if receipt.context.network.trim() != expected_network.trim() {
        return Err(Error::DisclosureVerification(format!(
            "network mismatch: expected {}, got {}",
            expected_network.trim(),
            receipt.context.network.trim(),
        )));
    }

    if let Some(expected_pool) = expected_pool
        && receipt.context.pool_address.trim() != expected_pool.trim()
    {
        return Err(Error::DisclosureVerification(format!(
            "pool mismatch: expected {}, got {}",
            expected_pool.trim(),
            receipt.context.pool_address.trim(),
        )));
    }

    if let Some(expected_authority) = expected_authority
        && !receipt
            .context
            .authority_identity_payload_hex
            .trim()
            .eq_ignore_ascii_case(expected_authority.trim())
    {
        return Err(Error::DisclosureVerification(format!(
            "authority mismatch: expected {}, got {}",
            expected_authority.trim(),
            receipt.context.authority_identity_payload_hex.trim(),
        )));
    }

    Ok(())
}

/// Verify a selective-disclosure receipt: Groth16 proof, context hash, root
/// freshness, and spent-nullifier status.
pub async fn verify_disclosure_receipt(
    fetcher: &StateFetcher,
    prover: &ProverHandle,
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
    expected_pool: Option<&str>,
    expected_authority: Option<&str>,
) -> Result<DisclosureVerificationReport, Error> {
    validate_receipt_context(
        receipt,
        &fetcher.contract_config().network,
        expected_pool,
        expected_authority,
    )?;

    let context_verified = crate::zk::disclosure::verify_receipt_context(receipt)
        .context("context verification failed")?;

    let proof_verified = prover
        .verify_disclosure_proof(receipt, expected_vk_hash)
        .await?;

    let pool_contract_id = receipt.context.pool_address.clone();
    let mut known_root_status = true;
    for root in &receipt.public_inputs.roots {
        let is_known = fetcher
            .is_pool_known_root(&pool_contract_id, *root)
            .await
            .context("root freshness check failed")?;
        if !is_known {
            known_root_status = false;
            break;
        }
    }

    let mut nullifiers_unspent = true;
    let mut spent_nullifier_indices = Vec::new();
    for (index, nullifier) in receipt.public_inputs.nullifiers.iter().enumerate() {
        let spent = fetcher
            .is_nullifier_spent(&pool_contract_id, *nullifier)
            .await
            .context("nullifier spent check failed")?;
        if spent {
            nullifiers_unspent = false;
            spent_nullifier_indices
                .push(u32::try_from(index).context("nullifier index out of u32 range")?);
        }
    }

    Ok(DisclosureVerificationReport {
        proof_verified,
        context_verified,
        known_root_status,
        nullifiers_unspent,
        spent_nullifier_indices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        DisclosureCircuitMetadata, DisclosureContext, DisclosurePublicInputs, Field,
    };

    fn test_receipt() -> DisclosureReceipt {
        DisclosureReceipt {
            version: 1,
            circuit: DisclosureCircuitMetadata {
                name: "selectiveDisclosure_1".to_string(),
                levels: 20,
                n_notes: 1,
                vk_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            },
            context: DisclosureContext {
                network: "testnet".to_string(),
                pool_address: "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
                authority_label: "Authority XYZ".to_string(),
                authority_identity_payload_hex: "0x617574686f72697479".to_string(),
                purpose: "kyc-review".to_string(),
                context_nonce: Field::ZERO,
            },
            public_inputs: DisclosurePublicInputs {
                roots: vec![],
                note_commitments: vec![],
                ext_context_hash: Field::ZERO,
                nullifiers: vec![],
                amounts: vec![],
            },
            proof_compressed_hex: "0x".to_string(),
            issued_at: "2026-10-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn validate_receipt_context_pool_match() {
        let receipt = test_receipt();
        assert!(
            validate_receipt_context(
                &receipt,
                "testnet",
                Some("CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn validate_receipt_context_pool_mismatch() {
        let receipt = test_receipt();
        let result = validate_receipt_context(
            &receipt,
            "testnet",
            Some("CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
            None,
        );
        assert!(
            matches!(result, Err(Error::DisclosureVerification(msg)) if msg.contains("pool mismatch"))
        );
    }

    #[test]
    fn validate_receipt_context_pool_none() {
        let receipt = test_receipt();
        assert!(validate_receipt_context(&receipt, "testnet", None, None).is_ok());
    }

    #[test]
    fn validate_receipt_context_network_match() {
        let receipt = test_receipt();
        assert!(validate_receipt_context(&receipt, "testnet", None, None).is_ok());
    }

    #[test]
    fn validate_receipt_context_network_mismatch() {
        let receipt = test_receipt();
        let result = validate_receipt_context(&receipt, "mainnet", None, None);
        assert!(
            matches!(result, Err(Error::DisclosureVerification(msg)) if msg.contains("network mismatch"))
        );
    }

    #[test]
    fn validate_receipt_context_authority_match() {
        let receipt = test_receipt();
        assert!(
            validate_receipt_context(&receipt, "testnet", None, Some("0x617574686f72697479"),)
                .is_ok()
        );
    }

    #[test]
    fn validate_receipt_context_authority_mismatch() {
        let receipt = test_receipt();
        let result = validate_receipt_context(&receipt, "testnet", None, Some("0xdeadbeef"));
        assert!(
            matches!(result, Err(Error::DisclosureVerification(msg)) if msg.contains("authority mismatch"))
        );
    }

    #[test]
    fn validate_receipt_context_authority_none() {
        let receipt = test_receipt();
        assert!(validate_receipt_context(&receipt, "testnet", None, None).is_ok());
    }
}
