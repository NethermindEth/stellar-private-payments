//! Seed a migrated SQLite wallet for integration tests.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use stellar_private_payments_sdk::{
    TransactChainContext,
    state::SqliteStorage,
    tx::{crypto, encryption, merkle::MerklePrefixTree},
};
use types::{
    AspNonMembershipProof, ContractEvent, ContractsEventData, Field, KeyDerivationSignature,
    LeafAddedEvent, NewCommitmentEvent, NoteAmount, NoteKeyPair, PolicyMode, SMT_DEPTH,
    SyncMetadata,
};

pub const POOL_MERKLE_LEVELS: u32 = 10;
pub const TEST_NETWORK: &str = "test";
const TEST_LEDGER: u32 = 1;

fn test_derivation_signature() -> KeyDerivationSignature {
    KeyDerivationSignature(vec![42u8; 64])
}

pub fn seeded_user_public_keys() -> Result<(types::NotePublicKey, types::EncryptionPublicKey)> {
    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature)?;
    Ok((note_keypair.public, encryption_keypair.public))
}

/// Open (or create) `path` with schema migrations applied.
pub fn ensure_schema(storage_path: &Path) -> Result<()> {
    let _storage = SqliteStorage::connect_file(storage_path).context("apply storage migrations")?;
    Ok(())
}

/// Seed keys, ASP membership, pool notes, and return a matching chain snapshot.
pub fn seed_prove_wallet(
    storage_path: &Path,
    pool_contract_id: &str,
    asp_membership_contract_id: &str,
    user_address: &str,
    network: &str,
    note_amounts: &[u64],
) -> Result<TransactChainContext> {
    ensure_schema(storage_path)?;

    let mut storage = SqliteStorage::connect_file(storage_path).context("open seeded database")?;

    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature.clone())?;
    let membership_blinding = encryption::derive_membership_blinding(&signature, network)?;

    storage.save_encryption_and_note_keypairs(
        user_address,
        &note_keypair,
        &encryption_keypair,
        &membership_blinding,
    )?;

    let user_membership_leaf =
        crypto::asp_membership_leaf(&note_keypair.public, &membership_blinding)?;

    let mut pool_leaves = Vec::with_capacity(note_amounts.len());
    let mut commitment_rows = Vec::with_capacity(note_amounts.len());

    for (leaf_index, &amount_u64) in note_amounts.iter().enumerate() {
        let amount = NoteAmount::from(u128::from(amount_u64));
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = u8::try_from(leaf_index)
            .context("leaf index fits in u8")?
            .saturating_add(1);
        let blinding = Field::try_from_le_bytes(blinding_le)?;

        let amount_field_le = Field::from(amount).to_le_bytes();
        let commitment_le = crypto::compute_commitment(
            &amount_field_le,
            note_keypair.public.as_ref(),
            &blinding.to_le_bytes(),
        )?;
        let commitment_le: [u8; 32] = commitment_le.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("commitment: expected 32 bytes, got {}", v.len())
        })?;
        let commitment = Field::try_from_le_bytes(commitment_le)?;

        let encrypted_output =
            encryption::encrypt_output_note(&encryption_keypair.public, amount, &blinding)?;

        let event_id = format!("test-pool-commit-{leaf_index}-{user_address}");
        storage.save_events_batch(&ContractsEventData {
            events: vec![ContractEvent {
                id: event_id.clone(),
                ledger: TEST_LEDGER,
                contract_id: pool_contract_id.to_string(),
                topics: vec!["commitment".to_string()],
                value: "dGVzdA==".to_string(),
            }],
            cursor: format!("pool-cur-{leaf_index}"),
            latest_ledger: TEST_LEDGER,
        })?;

        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: event_id,
            commitment,
            index: u32::try_from(leaf_index).context("leaf index")?,
            encrypted_output,
        }])?;

        pool_leaves.push(commitment);
        let expected_nullifier = expected_nullifier_for_note(
            &note_keypair,
            &commitment,
            u32::try_from(leaf_index).context("leaf index")?,
        )?;
        commitment_rows.push((commitment, amount, blinding, expected_nullifier));
    }

    let asp_membership_root = MerklePrefixTree::new(
        POOL_MERKLE_LEVELS,
        std::slice::from_ref(&user_membership_leaf),
    )?
    .into_built()
    .root()?;

    let asp_event_id = format!("test-asp-leaf-{user_address}");
    storage.save_events_batch(&ContractsEventData {
        events: vec![ContractEvent {
            id: asp_event_id.clone(),
            ledger: TEST_LEDGER,
            contract_id: asp_membership_contract_id.to_string(),
            topics: vec!["leaf_added".to_string()],
            value: "dGVzdA==".to_string(),
        }],
        cursor: "asp-cur".to_string(),
        latest_ledger: TEST_LEDGER,
    })?;

    storage.save_leaf_added_events_batch(&vec![LeafAddedEvent {
        id: asp_event_id,
        leaf: user_membership_leaf,
        index: 0,
        root: asp_membership_root,
    }])?;

    storage.save_sync_progress(
        &[SyncMetadata {
            contract_id: asp_membership_contract_id.to_string(),
            cursor: "asp-sync".to_string(),
            last_indexed_ledger: TEST_LEDGER,
            last_fully_indexed_ledger: 0,
        }],
        true,
    )?;

    insert_user_notes(storage_path, user_address, &commitment_rows)?;

    chain_snapshot_from_storage(
        storage_path,
        pool_contract_id,
        asp_membership_contract_id,
        network,
    )
}

/// Simulate on-chain effects of a prepared step for offline multi-tx tests.
pub fn apply_proved_step(
    storage_path: &Path,
    pool_contract_id: &str,
    asp_membership_contract_id: &str,
    user_address: &str,
    network: &str,
    prepared: &stellar_private_payments_sdk::PreparedTransaction,
) -> Result<TransactChainContext> {
    use stellar_private_payments_sdk::tx::notes;

    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature.clone())?;

    let mut storage =
        SqliteStorage::connect_file(storage_path).context("open storage for apply step")?;
    let mut conn = Connection::open(storage_path).context("open storage connection")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    let tx = conn.transaction()?;
    for nullifier in prepared.prepared.input_nullifiers {
        if nullifier.is_zero() {
            continue;
        }
        tx.execute(
            "DELETE FROM user_notes
             WHERE account_id = (SELECT id FROM accounts WHERE address = ?1)
               AND expected_nullifier = ?2",
            params![user_address, nullifier],
        )?;
    }
    tx.commit()?;

    let chain = chain_snapshot_from_storage(
        storage_path,
        pool_contract_id,
        asp_membership_contract_id,
        network,
    )?;
    let mut leaf_index = chain.pool_next_index;

    let outputs = [
        (
            prepared.prepared.output_commitments[0],
            prepared.ext_data.encrypted_output0.as_slice(),
        ),
        (
            prepared.prepared.output_commitments[1],
            prepared.ext_data.encrypted_output1.as_slice(),
        ),
    ];

    for (commitment, encrypted_output) in outputs {
        if commitment.is_zero() || encrypted_output.is_empty() {
            continue;
        }

        let Some(derived) = notes::try_decrypt_and_derive_user_note(
            &note_keypair,
            &encryption_keypair.private,
            &commitment,
            leaf_index,
            encrypted_output,
        )?
        else {
            continue;
        };

        let event_id = format!("test-pool-apply-{leaf_index}-{user_address}");
        storage.save_events_batch(&ContractsEventData {
            events: vec![ContractEvent {
                id: event_id.clone(),
                ledger: TEST_LEDGER,
                contract_id: pool_contract_id.to_string(),
                topics: vec!["commitment".to_string()],
                value: "dGVzdA==".to_string(),
            }],
            cursor: format!("pool-apply-cur-{leaf_index}"),
            latest_ledger: TEST_LEDGER,
        })?;

        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: event_id,
            commitment,
            index: leaf_index,
            encrypted_output: encrypted_output.to_vec(),
        }])?;

        insert_user_notes(
            storage_path,
            user_address,
            &[(
                commitment,
                derived.amount,
                derived.blinding,
                derived.expected_nullifier,
            )],
        )?;

        leaf_index = leaf_index.saturating_add(1);
    }

    chain_snapshot_from_storage(
        storage_path,
        pool_contract_id,
        asp_membership_contract_id,
        network,
    )
}

fn chain_snapshot_from_storage(
    storage_path: &Path,
    pool_contract_id: &str,
    asp_membership_contract_id: &str,
    _network: &str,
) -> Result<TransactChainContext> {
    let storage =
        SqliteStorage::connect_file(storage_path).context("open storage for chain snapshot")?;
    let signature = test_derivation_signature();
    let (note_keypair, _) = encryption::derive_encryption_and_note_keypairs(signature)?;
    let note_pubkey_field = Field::try_from_le_bytes(*note_keypair.public.as_ref())?;

    let pool_leaves = storage.get_pool_commitment_leaves_ordered(pool_contract_id)?;
    let pool_root = MerklePrefixTree::new(POOL_MERKLE_LEVELS, &pool_leaves)?
        .into_built()
        .root()?;
    let pool_next_index = u32::try_from(pool_leaves.len()).context("pool leaf count")?;

    let asp_leaves = storage.get_all_asp_membership_leaves_ordered(asp_membership_contract_id)?;
    let asp_membership_root = MerklePrefixTree::new(POOL_MERKLE_LEVELS, &asp_leaves)?
        .into_built()
        .root()?;

    Ok(TransactChainContext {
        pool_root,
        pool_next_index,
        pool_merkle_levels: POOL_MERKLE_LEVELS,
        asp_membership_root,
        asp_membership_contract_id: asp_membership_contract_id.to_string(),
        asp_membership_ledger: TEST_LEDGER,
        non_membership_proof: AspNonMembershipProof {
            key: note_pubkey_field,
            old_key: Field::ZERO,
            old_value: Field::ZERO,
            is_old0: true,
            siblings: vec![Field::ZERO; SMT_DEPTH as usize],
            root: Field::ZERO,
        },
        policy_mode: PolicyMode::Both,
    })
}

fn expected_nullifier_for_note(
    note_keypair: &NoteKeyPair,
    commitment: &Field,
    leaf_index: u32,
) -> Result<Field> {
    let commitment_le = commitment.to_le_bytes();
    let mut path_indices_le = [0u8; 32];
    path_indices_le[..8].copy_from_slice(&u64::from(leaf_index).to_le_bytes());
    let signature =
        crypto::compute_signature(&note_keypair.private.0, &commitment_le, &path_indices_le)?;
    let expected_nullifier =
        crypto::compute_nullifier(&commitment_le, &path_indices_le, &signature)?;
    let expected_nullifier: [u8; 32] = expected_nullifier
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("nullifier: expected 32 bytes, got {}", v.len()))?;
    Field::try_from_le_bytes(expected_nullifier).context("nullifier field")
}

fn insert_user_notes(
    storage_path: &Path,
    user_address: &str,
    rows: &[(Field, NoteAmount, Field, Field)],
) -> Result<()> {
    let mut conn = Connection::open(storage_path).context("open seeded database for user_notes")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    let tx = conn.transaction()?;
    let account_id: i64 = tx.query_row(
        "SELECT id FROM accounts WHERE address = ?1",
        params![user_address],
        |row| row.get(0),
    )?;

    for (commitment, amount, blinding, expected_nullifier) in rows {
        let commitment_id: i64 = tx.query_row(
            "SELECT id FROM pool_commitments WHERE commitment = ?1",
            params![commitment],
            |row| row.get(0),
        )?;

        tx.execute(
            "INSERT INTO user_notes (
                id,
                account_id,
                commitment_id,
                expected_nullifier,
                blinding,
                amount
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(id) DO NOTHING",
            params![
                commitment,
                account_id,
                commitment_id,
                expected_nullifier,
                blinding,
                amount.to_string(),
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}
