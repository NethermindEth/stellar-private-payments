//! Transact witness input building and prepared-transaction types.

use crate::{
    Error,
    chain::{OnchainProofPublicInputs, PreparedSorobanTx},
    planner::Transact,
    state::{SqliteStorage, StoredPrivateKeys},
    types::{
        AspMembershipProof, AspMembershipSync, AspNonMembershipProof, BabyJubJubPoint,
        EncryptionKeyPair, EncryptionPublicKey, ExtAmount, ExtData, Field, GlobalViewKeyCiphertext,
        GvkMode, NoteAmount, NoteKeyPair, NotePrivateKey, NotePublicKey, PolicyFlags, SMT_DEPTH,
        TransactChainContext,
    },
    zk::{
        crypto::asp_membership_leaf,
        encryption::generate_random_blinding,
        flows::{N_OUTPUTS, TransactInputNote, TransactOutput, TransactParams},
        merkle::{MerklePrefixTree, MerklePrefixTreeBuilt, MerkleProof},
    },
};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactRequest {
    pub user_address: String,
    pub kdf_domain: String,
    pub pool_root: Option<Field>,
    pub pool_next_index: u32,
    pub pool_address: String,
    /// This pool's configured token contract, for the domain-bound
    /// `ext_data_hash`. Sourced from `TransactChainContext::token_contract_id`.
    pub token_address: String,
    pub ext_recipient: String,
    pub ext_amount: ExtAmount,
    pub fee: NoteAmount,
    pub aspmem_root: Field,
    pub aspmem_contract_id: String,
    pub aspmem_ledger: u32,
    pub input_commitments: Vec<Field>,
    pub output_amounts: [NoteAmount; N_OUTPUTS],
    pub out_recipient_note_pubkeys: [Option<NotePublicKey>; N_OUTPUTS],
    pub out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; N_OUTPUTS],
    pub smt_depth: u32,
    pub tree_depth: u32,
    pub asp_depth: u32,
    pub non_membership_proof: Option<AspNonMembershipProof>,
    pub policy_flags: PolicyFlags,
    pub gvk_mode: GvkMode,
    pub admin_view_key: Option<BabyJubJubPoint>,
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
    pub output_gvk_ciphertexts: Option<[GlobalViewKeyCiphertext; 2]>,
    pub input_gvk_ciphertexts: Option<Vec<GlobalViewKeyCiphertext>>,
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
            output_gvk_ciphertexts: p.output_gvk_ciphertexts.clone(),
            input_gvk_ciphertexts: p.input_gvk_ciphertexts.clone(),
        }
    }
}

pub enum BuildTransactParams {
    Ready(Box<TransactParams>),
    MembershipSync(AspMembershipSync),
}

pub(crate) fn transact_request_from_step(
    step: &Transact,
    user_address: &str,
    kdf_domain: &str,
    pool_address: &str,
    chain: &TransactChainContext,
) -> TransactRequest {
    TransactRequest {
        user_address: user_address.to_string(),
        kdf_domain: kdf_domain.to_string(),
        pool_root: Some(chain.pool_root),
        pool_next_index: chain.pool_next_index,
        pool_address: pool_address.to_string(),
        token_address: chain.token_contract_id.clone(),
        ext_recipient: step.ext_recipient.clone(),
        ext_amount: step.ext_amount,
        fee: chain.fee,
        aspmem_root: chain.asp_membership_root,
        aspmem_contract_id: chain.asp_membership_contract_id.clone(),
        aspmem_ledger: chain.asp_membership_ledger,
        input_commitments: step.input_commitments.clone(),
        output_amounts: step.output_amounts,
        out_recipient_note_pubkeys: step.out_recipient_note_pubkeys.clone(),
        out_recipient_encryption_pubkeys: step.out_recipient_encryption_pubkeys.clone(),
        smt_depth: SMT_DEPTH,
        tree_depth: chain.pool_merkle_levels,
        asp_depth: chain.asp_membership_levels,
        non_membership_proof: chain.non_membership_proof.clone(),
        policy_flags: chain.policy_flags,
        gvk_mode: chain.gvk_mode,
        admin_view_key: chain.admin_view_key.clone(),
    }
}

/// A pool's deposit rules, checked before a proof is built.
pub(crate) struct DepositLimits {
    paused: bool,
    fee: NoteAmount,
    minimum: NoteAmount,
    maximum: ExtAmount,
}

impl From<&TransactChainContext> for DepositLimits {
    fn from(chain: &TransactChainContext) -> Self {
        Self {
            paused: chain.deposits_paused,
            fee: chain.fee,
            minimum: chain.minimum_deposit_amount,
            maximum: chain.maximum_deposit_amount,
        }
    }
}

impl DepositLimits {
    /// Refuses a deposit the pool would refuse. Transfers and withdrawals pass.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DepositsPaused`] while `pool` is paused, then
    /// [`Error::DepositAboveMaximum`] when the deposit sends more than the
    /// maximum, then [`Error::DepositBelowMinimum`] when it leaves less than
    /// the minimum in notes after the fee. The pool checks them in this
    /// order.
    pub(crate) fn check(&self, ext_amount: ExtAmount, pool: &str) -> Result<(), Error> {
        if ext_amount <= ExtAmount::ZERO {
            return Ok(());
        }
        if self.paused {
            return Err(Error::DepositsPaused {
                pool: pool.to_string(),
            });
        }
        if ext_amount > self.maximum {
            return Err(Error::DepositAboveMaximum {
                maximum: self.maximum,
                largest_deposit: NoteAmount::try_from(self.maximum)
                    .ok()
                    .and_then(|maximum| maximum.checked_sub(self.fee))
                    .unwrap_or_default(),
            });
        }
        let net = NoteAmount::try_from(ext_amount)?.checked_sub(self.fee);
        if net.is_none_or(|net| net < self.minimum) {
            return Err(Error::DepositBelowMinimum {
                minimum: self.minimum,
            });
        }
        Ok(())
    }
}

pub fn build_transact_params(
    storage: &SqliteStorage,
    req: &TransactRequest,
) -> Result<BuildTransactParams, Error> {
    if req.input_commitments.len() > 2 {
        return Err(Error::Other(anyhow::anyhow!(
            "transact input_commitments must have length 0..=2"
        )));
    }

    let (note_privkey, note_pubkey, encryption_pubkey, membership_blinding) =
        load_user_key_material(storage, &req.user_address, &req.kdf_domain)?;

    let membership_proof = if req.policy_flags.requires_membership_proofs() {
        match build_membership_proof(
            storage,
            &req.aspmem_contract_id,
            &note_pubkey,
            membership_blinding,
            req.aspmem_root,
            req.aspmem_ledger,
            req.asp_depth,
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

    let inputs = match build_pool_inputs(storage, req, pool_root)? {
        Ok(inputs) => inputs,
        Err(status) => return Ok(BuildTransactParams::MembershipSync(status)),
    };

    let mut outputs = Vec::with_capacity(N_OUTPUTS);
    for i in 0..N_OUTPUTS {
        let note_pk = req.out_recipient_note_pubkeys[i].clone();
        let enc_pk = req.out_recipient_encryption_pubkeys[i].clone();
        if note_pk.is_some() != enc_pk.is_some() {
            return Err(Error::Other(anyhow::anyhow!(
                "output {i}: recipient_note_pubkey and recipient_encryption_pubkey must both be set or both be null"
            )));
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
        pool_address: req.pool_address.clone(),
        token_address: req.token_address.clone(),
        ext_recipient: req.ext_recipient.clone(),
        ext_amount: req.ext_amount,
        fee: req.fee,
        inputs,
        outputs,
        membership_proof,
        non_membership_proof: req.non_membership_proof.clone(),
        tree_depth: req.tree_depth,
        asp_depth: req.asp_depth,
        smt_depth: req.smt_depth,
        policy_flags: req.policy_flags,
        gvk_mode: req.gvk_mode,
        admin_view_key: req.admin_view_key.clone(),
    })))
}

pub(crate) fn load_user_key_material(
    storage: &SqliteStorage,
    user_address: &str,
    kdf_domain: &str,
) -> Result<(NotePrivateKey, NotePublicKey, EncryptionPublicKey, Field), Error> {
    let StoredPrivateKeys {
        note_keypair: NoteKeyPair {
            private,
            public: note_pub,
        },
        encryption_keypair: EncryptionKeyPair {
            public: enc_pub, ..
        },
        membership_blinding,
    } = crate::storage::map_private_keys(storage, user_address, kdf_domain)?;

    Ok((private, note_pub, enc_pub, membership_blinding))
}

fn build_membership_proof(
    storage: &SqliteStorage,
    aspmem_contract_id: &str,
    note_pubkey: &NotePublicKey,
    membership_blinding: Field,
    aspmem_root: Field,
    aspmem_ledger: u32,
    asp_depth: u32,
) -> Result<Result<AspMembershipProof, AspMembershipSync>, Error> {
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
        MerklePrefixTree::new(asp_depth, &asp_membership_merkle_tree_leaves)?.into_built();
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
    req: &TransactRequest,
    expected_pool_root: Field,
) -> Result<Result<Vec<TransactInputNote>, AspMembershipSync>> {
    if req.input_commitments.is_empty() {
        return Ok(Ok(Vec::new()));
    }

    let tree = match build_validated_pool_tree(
        storage,
        &req.pool_address,
        req.pool_next_index,
        req.tree_depth,
        expected_pool_root,
    )? {
        Ok(tree) => tree,
        Err(status) => return Ok(Err(status)),
    };

    let mut out = Vec::with_capacity(req.input_commitments.len());
    for commitment in &req.input_commitments {
        let Some((amount, blinding, leaf_index)) = storage.get_unspent_user_note_by_commitment(
            &req.pool_address,
            &req.user_address,
            &req.kdf_domain,
            commitment,
        )?
        else {
            tracing::info!(
                commitment = ?crate::types::Sensitive(commitment),
                "unspent note not found for commitment; waiting for note derivation"
            );
            return Ok(Err(AspMembershipSync::SyncRequired(None)));
        };

        out.push(build_pool_input_note(amount, blinding, leaf_index, &tree)?);
    }

    Ok(Ok(out))
}

pub(crate) fn build_validated_pool_tree(
    storage: &SqliteStorage,
    pool_address: &str,
    pool_next_index: u32,
    tree_depth: u32,
    expected_pool_root: Field,
) -> Result<Result<MerklePrefixTreeBuilt, AspMembershipSync>> {
    let leaves = storage.get_pool_commitment_leaves_ordered(pool_address)?;

    if leaves.len() != pool_next_index as usize {
        tracing::info!(
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
    amount: crate::types::NoteAmount,
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

#[cfg(test)]
mod tests {
    use super::{
        DepositLimits, build_validated_pool_tree, load_user_key_material,
        transact_request_from_step,
    };
    use crate::{
        Error,
        planner::Transact,
        state::SqliteStorage,
        types::{
            AspMembershipSync, ExtAmount, Field, GvkMode, NoteAmount, PolicyFlags,
            TransactChainContext, lock_reveal_flag, set_reveal_sensitive,
        },
        zk::merkle::MerklePrefixTree,
    };

    const ADDRESS: &str = "GTESTACCOUNTWITHNOSTOREDKEYS";
    const LEVELS: u32 = 2;

    /// An empty local tree has the expected root, so only the leaf count can
    /// refuse it.
    #[test]
    fn pool_tree_behind_the_chain_requires_sync() -> anyhow::Result<()> {
        let storage = SqliteStorage::connect_in_memory()?;
        let empty_root = MerklePrefixTree::new(LEVELS, &[])?.into_built().root()?;

        let tree = build_validated_pool_tree(&storage, "CPOOL", 2, LEVELS, empty_root)?;
        assert!(matches!(tree, Err(AspMembershipSync::SyncRequired(None))));
        Ok(())
    }

    /// An empty local tree matches a chain with no leaves, so only the root can
    /// refuse it.
    #[test]
    fn pool_tree_with_a_wrong_root_is_refused() -> anyhow::Result<()> {
        let storage = SqliteStorage::connect_in_memory()?;

        let Err(err) = build_validated_pool_tree(&storage, "CPOOL", 0, LEVELS, Field::ZERO) else {
            panic!("a wrong root must be refused");
        };
        assert!(err.to_string().starts_with("pool root mismatch"), "{err}");
        Ok(())
    }

    /// Returns the chain context of a pool with fee 5, minimum 10, and
    /// maximum 100.
    fn chain(deposits_paused: bool) -> TransactChainContext {
        TransactChainContext {
            pool_root: Field::ZERO,
            pool_next_index: 0,
            pool_merkle_levels: 10,
            token_contract_id: "TOKEN".into(),
            asp_membership_levels: 10,
            asp_membership_root: Field::ZERO,
            asp_membership_contract_id: "ASP".into(),
            asp_membership_ledger: 0,
            non_membership_proof: None,
            policy_flags: PolicyFlags::EMPTY,
            gvk_mode: GvkMode::Off,
            admin_view_key: None,
            deposits_paused,
            fee: NoteAmount::from(5),
            minimum_deposit_amount: NoteAmount::from(10),
            maximum_deposit_amount: ExtAmount::from(100),
        }
    }

    /// Checks `ext_amount` against the pool of [`chain`].
    fn check(ext_amount: i128, deposits_paused: bool) -> Result<(), Error> {
        DepositLimits::from(&chain(deposits_paused)).check(ExtAmount::from(ext_amount), "POOL")
    }

    #[test]
    fn a_request_carries_the_chain_fee() {
        let step = Transact::new(
            Vec::new(),
            [NoteAmount::ZERO; 2],
            ExtAmount::from(15),
            "POOL".into(),
            [None, None],
            [None, None],
        );
        let req = transact_request_from_step(&step, ADDRESS, "tests", "POOL", &chain(false));
        assert_eq!(req.fee, NoteAmount::from(5));
    }

    /// A deposit of 14 leaves 9 in notes after the fee of 5, and one of 3 does
    /// not cover the fee.
    #[test]
    fn a_deposit_below_the_minimum_is_refused() {
        for ext_amount in [14, 3] {
            assert!(
                matches!(
                    check(ext_amount, false),
                    Err(Error::DepositBelowMinimum { minimum }) if minimum == NoteAmount::from(10)
                ),
                "a deposit of {ext_amount} must be refused"
            );
        }
    }

    /// A deposit of 15 leaves exactly the minimum. Transfers and withdrawals
    /// pass even while deposits are paused.
    #[test]
    fn a_deposit_at_the_minimum_a_transfer_and_a_withdrawal_pass() {
        check(15, false).expect("the minimum admits a deposit of 15");
        for (ext_amount, deposits_paused) in [(0, false), (-1, false), (0, true), (-1, true)] {
            check(ext_amount, deposits_paused).expect("a transfer or a withdrawal passes");
        }
    }

    /// The deposit is below the minimum, so a minimum check ahead of the pause
    /// would answer `DepositBelowMinimum` instead.
    #[test]
    fn a_paused_pool_reports_the_pause_before_the_minimum() {
        assert!(matches!(
            check(3, true),
            Err(Error::DepositsPaused { pool }) if pool == "POOL"
        ));
    }

    /// The pool caps what a deposit sends, fee included, so 100 passes and 101
    /// does not. The largest deposit leaves room for the fee of 5.
    #[test]
    fn a_deposit_above_the_maximum_is_refused() {
        assert!(matches!(
            check(101, false),
            Err(Error::DepositAboveMaximum { maximum, largest_deposit })
                if maximum == ExtAmount::from(100) && largest_deposit == NoteAmount::from(95)
        ));
        check(100, false).expect("the maximum admits a deposit that sends exactly it");
    }

    /// The deposit is above the maximum, so a maximum check ahead of the pause
    /// would answer `DepositAboveMaximum` instead.
    #[test]
    fn a_paused_pool_reports_the_pause_before_the_maximum() {
        assert!(matches!(
            check(101, true),
            Err(Error::DepositsPaused { pool }) if pool == "POOL"
        ));
    }

    #[test]
    fn missing_user_keys_error_redacts_the_address() {
        let _guard = lock_reveal_flag();
        set_reveal_sensitive(false);
        let storage = SqliteStorage::connect_in_memory().expect("in-memory storage");

        let err =
            load_user_key_material(&storage, ADDRESS, "tests").expect_err("no keys are stored");
        let rendered = format!("{err:#}");

        assert!(!rendered.contains(ADDRESS), "address leaked: {rendered}");
        assert!(rendered.contains("<redacted>"), "not redacted: {rendered}");
    }
}
