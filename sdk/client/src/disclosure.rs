//! Selective-disclosure witness building and verification helpers.

pub use ::disclosure::{vk_hash_hex, *};
pub use types::DisclosureContext;

use serde::{Deserialize, Serialize};
use state::SqliteStorage;
use types::{
    AspMembershipSync, DisclosureReceipt, DisclosureVerificationReport, Field, NoteAmount,
    NotePrivateKey,
};

use crate::{
    error::Error,
    prover::Prover,
    transact::{build_validated_pool_tree, load_user_key_material},
};
use prover::merkle::MerkleProof;
use stellar::StateFetcher;

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
        load_user_key_material(storage, &req.user_address)?;

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
            .get_user_note_by_commitment(&req.pool_address, &req.user_address, commitment)?
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
    match result.map_err(|e| Error::Other(e.to_string()))? {
        BuildDisclosureInputs::Ready(inputs) => Ok(inputs),
        BuildDisclosureInputs::MembershipSync(status) => Err(Error::MembershipSync(status)),
    }
}

/// Verify a selective-disclosure receipt: Groth16 proof, context hash, root
/// freshness, and spent-nullifier status.
pub async fn verify_disclosure_receipt(
    fetcher: &StateFetcher,
    prover: &dyn Prover,
    receipt: &DisclosureReceipt,
    expected_vk_hash: &str,
) -> Result<DisclosureVerificationReport, Error> {
    let proof_verified = prover
        .verify_disclosure_proof(receipt, expected_vk_hash)
        .await?;
    let context_verified = ::disclosure::verify_receipt_context(receipt)
        .map_err(|e| Error::Other(format!("context verification failed: {e}")))?;

    let pool_contract_id = receipt.context.pool_address.clone();
    let mut known_root_status = true;
    for root in &receipt.public_inputs.roots {
        let is_known = fetcher
            .is_pool_known_root(&pool_contract_id, *root)
            .await
            .map_err(|e| Error::Other(format!("root freshness check failed: {e:#}")))?;
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
            .map_err(|e| Error::Other(format!("nullifier spent check failed: {e:#}")))?;
        if spent {
            nullifiers_unspent = false;
            spent_nullifier_indices.push(
                u32::try_from(index)
                    .map_err(|_| Error::Other("nullifier index out of u32 range".to_string()))?,
            );
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
