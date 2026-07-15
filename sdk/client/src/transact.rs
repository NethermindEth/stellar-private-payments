//! Transact witness input building and prepared-transaction types.

use anyhow::Result;
use prover::{
    crypto::asp_membership_leaf,
    encryption::generate_random_blinding,
    flows::{N_OUTPUTS, TransactInputNote, TransactOutput, TransactParams},
    merkle::{MerklePrefixTree, MerklePrefixTreeBuilt, MerkleProof},
};
use serde::{Deserialize, Serialize};
use state::{SqliteStorage, StoredUserKeys};
use stellar::{OnchainProofPublicInputs, PreparedSorobanTx};
use tx_planner::Transact;
use types::{
    AspMembershipProof, AspMembershipSync, AspNonMembershipProof, EncryptionKeyPair,
    EncryptionPublicKey, ExtAmount, ExtData, Field, NoteAmount, NoteKeyPair, NotePrivateKey,
    NotePublicKey, PolicyFlags, SMT_DEPTH, TransactChainContext,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactRequest {
    pub user_address: String,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub pool_address: String,
    pub ext_recipient: String,
    pub ext_amount: ExtAmount,
    pub aspmem_root: Field,
    pub aspmem_contract_id: String,
    pub aspmem_ledger: u32,
    pub input_commitments: Vec<Field>,
    pub output_amounts: [NoteAmount; N_OUTPUTS],
    pub out_recipient_note_pubkeys: [Option<NotePublicKey>; N_OUTPUTS],
    pub out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; N_OUTPUTS],
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub non_membership_proof: Option<AspNonMembershipProof>,
    pub policy_flags: PolicyFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTxPublic {
    pub pool_root: Field,
    pub input_nullifiers: [Field; 2],
    pub output_commitments: [Field; 2],
    pub public_amount: Field,
    pub ext_data_hash_be: [u8; 32],
    pub asp_membership_root: Field,
    pub asp_non_membership_root: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedProverTx {
    pub proof_uncompressed: Vec<u8>,
    pub ext_data: ExtData,
    pub prepared: PreparedTxPublic,
    pub soroban_tx: PreparedSorobanTx,
}

impl From<&PreparedTxPublic> for OnchainProofPublicInputs {
    fn from(p: &PreparedTxPublic) -> Self {
        Self {
            root: p.pool_root,
            input_nullifiers: p.input_nullifiers,
            output_commitment0: p.output_commitments[0],
            output_commitment1: p.output_commitments[1],
            public_amount: p.public_amount,
            ext_data_hash_be: p.ext_data_hash_be,
            asp_membership_root: p.asp_membership_root,
            asp_non_membership_root: p.asp_non_membership_root,
        }
    }
}

pub enum BuildTransactParams {
    Ready(Box<TransactParams>),
    MembershipSync(AspMembershipSync),
}

pub fn transact_request_from_step(
    step: &Transact,
    user_address: &str,
    pool_address: &str,
    chain: &TransactChainContext,
) -> TransactRequest {
    TransactRequest {
        user_address: user_address.to_string(),
        pool_root: Some(chain.pool_root),
        pool_next_index: chain.pool_next_index,
        pool_address: pool_address.to_string(),
        ext_recipient: step.ext_recipient.clone(),
        ext_amount: step.ext_amount,
        aspmem_root: chain.asp_membership_root,
        aspmem_contract_id: chain.asp_membership_contract_id.clone(),
        aspmem_ledger: chain.asp_membership_ledger,
        input_commitments: step.input_commitments.clone(),
        output_amounts: step.output_amounts,
        out_recipient_note_pubkeys: step.out_recipient_note_pubkeys.clone(),
        out_recipient_encryption_pubkeys: step.out_recipient_encryption_pubkeys.clone(),
        smt_depth: SMT_DEPTH,
        tree_depth: chain.pool_merkle_levels,
        non_membership_proof: chain.non_membership_proof.clone(),
        policy_flags: chain.policy_flags,
    }
}

pub fn build_transact_params(
    storage: &SqliteStorage,
    req: &TransactRequest,
) -> Result<BuildTransactParams> {
    if req.input_commitments.len() > 2 {
        anyhow::bail!("transact input_commitments must have length 0..=2");
    }

    let (note_privkey, note_pubkey, encryption_pubkey, membership_blinding) =
        load_user_key_material(storage, &req.user_address)?;

    let membership_proof = if req.policy_flags.requires_membership_proofs() {
        match build_membership_proof(
            storage,
            &req.aspmem_contract_id,
            &note_pubkey,
            membership_blinding,
            req.aspmem_root,
            req.aspmem_ledger,
            req.tree_depth,
        )? {
            Ok(proof) => Some(proof),
            Err(status) => return Ok(BuildTransactParams::MembershipSync(status)),
        }
    } else {
        None
    };

    let pool_root = req
        .pool_root
        .ok_or_else(|| anyhow::anyhow!("missing pool_root"))?;

    let inputs = match build_pool_inputs(
        storage,
        &req.user_address,
        &req.pool_address,
        req.pool_next_index,
        req.tree_depth,
        pool_root,
        &req.input_commitments,
    )? {
        Ok(inputs) => inputs,
        Err(status) => return Ok(BuildTransactParams::MembershipSync(status)),
    };

    let mut outputs = Vec::with_capacity(N_OUTPUTS);
    for i in 0..N_OUTPUTS {
        let note_pk = req.out_recipient_note_pubkeys[i].clone();
        let enc_pk = req.out_recipient_encryption_pubkeys[i].clone();
        if note_pk.is_some() != enc_pk.is_some() {
            anyhow::bail!(
                "output {i}: recipient_note_pubkey and recipient_encryption_pubkey must both be set or both be null"
            );
        }
        outputs.push(TransactOutput {
            amount: req.output_amounts[i],
            blinding: generate_random_blinding()?,
            recipient_note_pubkey: note_pk,
            recipient_encryption_pubkey: enc_pk,
        });
    }

    Ok(BuildTransactParams::Ready(Box::new(TransactParams {
        priv_key: note_privkey,
        encryption_pubkey,
        pool_root,
        ext_recipient: req.ext_recipient.clone(),
        ext_amount: req.ext_amount,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof: req.non_membership_proof.clone(),
        tree_depth: req.tree_depth,
        smt_depth: req.smt_depth,
        policy_flags: req.policy_flags,
    })))
}

pub fn load_user_key_material(
    storage: &SqliteStorage,
    user_address: &str,
) -> Result<(NotePrivateKey, NotePublicKey, EncryptionPublicKey, Field)> {
    let StoredUserKeys {
        note_keypair: NoteKeyPair {
            private,
            public: note_pub,
        },
        encryption_keypair: EncryptionKeyPair {
            public: enc_pub, ..
        },
        membership_blinding,
    } = storage.get_user_keys(user_address)?.ok_or_else(|| {
        anyhow::anyhow!("address {user_address} should generate privacy keys and ASP secret first")
    })?;

    Ok((private, note_pub, enc_pub, membership_blinding))
}

fn build_membership_proof(
    storage: &SqliteStorage,
    aspmem_contract_id: &str,
    note_pubkey: &NotePublicKey,
    membership_blinding: Field,
    aspmem_root: Field,
    aspmem_ledger: u32,
    tree_depth: u32,
) -> Result<Result<AspMembershipProof, AspMembershipSync>> {
    let user_leaf = asp_membership_leaf(note_pubkey, &membership_blinding)?;
    let user_leaf_index = match storage.check_asp_membership_precondition(
        aspmem_contract_id,
        &user_leaf,
        &aspmem_root,
        aspmem_ledger,
    )? {
        AspMembershipSync::UserIndex(user_leaf_index) => user_leaf_index,
        status => return Ok(Err(status)),
    };

    let asp_membership_merkle_tree_leaves =
        storage.get_all_asp_membership_leaves_ordered(aspmem_contract_id)?;
    let aspmembership_tree =
        MerklePrefixTree::new(tree_depth, &asp_membership_merkle_tree_leaves)?.into_built();
    let MerkleProof {
        path_indices,
        path_elements,
        root,
        ..
    } = aspmembership_tree.proof(user_leaf_index)?;

    Ok(Ok(AspMembershipProof {
        leaf: user_leaf,
        blinding: membership_blinding,
        path_elements,
        path_indices,
        root,
    }))
}

fn build_pool_inputs(
    storage: &SqliteStorage,
    user_address: &str,
    pool_address: &str,
    pool_next_index: u32,
    tree_depth: u32,
    expected_pool_root: Field,
    input_commitments: &[Field],
) -> Result<Result<Vec<TransactInputNote>, AspMembershipSync>> {
    if input_commitments.is_empty() {
        return Ok(Ok(Vec::new()));
    }

    let tree = match build_validated_pool_tree(
        storage,
        pool_address,
        pool_next_index,
        tree_depth,
        expected_pool_root,
    )? {
        Ok(tree) => tree,
        Err(status) => return Ok(Err(status)),
    };

    let mut out = Vec::with_capacity(input_commitments.len());
    for commitment in input_commitments {
        let Some((amount, blinding, leaf_index)) =
            storage.get_unspent_user_note_by_commitment(pool_address, user_address, commitment)?
        else {
            log::info!(
                "unspent note not found for commitment {commitment}; waiting for note derivation"
            );
            return Ok(Err(AspMembershipSync::SyncRequired(None)));
        };

        out.push(build_pool_input_note(amount, blinding, leaf_index, &tree)?);
    }

    Ok(Ok(out))
}

pub fn build_validated_pool_tree(
    storage: &SqliteStorage,
    pool_address: &str,
    pool_next_index: u32,
    tree_depth: u32,
    expected_pool_root: Field,
) -> Result<Result<MerklePrefixTreeBuilt, AspMembershipSync>> {
    let leaves = storage.get_pool_commitment_leaves_ordered(pool_address)?;

    if leaves.len() != pool_next_index as usize {
        log::info!(
            "pool commitments not synced: local={}, chain={}",
            leaves.len(),
            pool_next_index
        );
        return Ok(Err(AspMembershipSync::SyncRequired(None)));
    }

    let tree = MerklePrefixTree::new(tree_depth, &leaves)?.into_built();
    let computed_root = tree.root()?;
    if computed_root != expected_pool_root {
        anyhow::bail!("pool root mismatch: local computed root does not match on-chain root");
    }

    Ok(Ok(tree))
}

fn build_pool_input_note(
    amount: types::NoteAmount,
    blinding: Field,
    leaf_index: u32,
    tree: &MerklePrefixTreeBuilt,
) -> Result<TransactInputNote> {
    let MerkleProof {
        path_elements,
        path_indices,
        ..
    } = tree.proof(leaf_index)?;

    Ok(TransactInputNote {
        amount,
        blinding,
        merkle_path_elements: path_elements,
        merkle_path_indices: path_indices,
    })
}
