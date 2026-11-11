//! Seed a migrated SQLite wallet for integration tests.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::params;
use stellar_private_payments::{
    chain::EventChain,
    state::SqliteStorage,
    types::{
        AspNonMembershipProof, ContractEvent, ContractsEventData, ExtAmount, Field, GvkMode,
        KeyDerivationSignature, LeafAddedEvent, NewCommitmentEvent, NoteAmount, NoteKeyPair,
        PolicyFlags, SMT_DEPTH, SyncMetadata, TransactChainContext,
    },
    zk::{crypto, encryption, merkle::MerklePrefixTree},
};
use stellar_xdr::{Limits, ScBytes, ScMap, ScMapEntry, ScSymbol, ScVal, UInt256Parts, WriteXdr};

/// Synthetic encryption key shared by this test fixture's connections.
pub fn database_key() -> stellar_private_payments::state::database_key::DatabaseKey {
    stellar_private_payments::state::database_key::DatabaseKey::new([42; 32])
}

fn open_storage(path: &Path) -> Result<SqliteStorage> {
    use stellar_private_payments::state::database_key::OpenPurpose;
    SqliteStorage::connect_encrypted(
        path,
        &database_key(),
        if path.exists() {
            OpenPurpose::OpenExisting
        } else {
            OpenPurpose::CreateNew
        },
    )
}

fn open_connection(path: &Path) -> Result<rusqlite::Connection> {
    stellar_private_payments::state::database_key::open_connection(
        path,
        &database_key(),
        stellar_private_payments::state::database_key::OpenPurpose::OpenExisting,
    )
}

pub const POOL_MERKLE_LEVELS: u32 = 20;
pub const ASP_MEMBERSHIP_LEVELS: u32 = 10;
pub const TEST_NETWORK: &str = "test";
pub const TEST_KDF_DOMAIN: &str = "tests";
const TEST_LEDGER: u32 = 1;

fn test_derivation_signature() -> KeyDerivationSignature {
    KeyDerivationSignature(vec![42u8; 64])
}

pub fn seeded_user_public_keys() -> Result<(
    stellar_private_payments::types::NotePublicKey,
    stellar_private_payments::types::EncryptionPublicKey,
)> {
    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature)?;
    Ok((note_keypair.public, encryption_keypair.public))
}

/// The nullifier the seeded wallet's note at `leaf_index` publishes when
/// spent.
pub fn seeded_note_nullifier(commitment: &Field, leaf_index: u32) -> Result<Field> {
    let (note_keypair, _) =
        encryption::derive_encryption_and_note_keypairs(test_derivation_signature())?;
    expected_nullifier_for_note(&note_keypair, commitment, leaf_index)
}

/// Open (or create) `path` with schema migrations applied.
pub fn ensure_schema(storage_path: &Path) -> Result<()> {
    let _storage = open_storage(storage_path).context("apply storage migrations")?;
    Ok(())
}

/// Seed keys, ASP membership, pool notes, and return a matching chain snapshot.
pub fn seed_prove_wallet(
    storage_path: &Path,
    pool_contract_id: &str,
    token_contract_id: &str,
    asp_membership_contract_id: &str,
    user_address: &str,
    network: &str,
    note_amounts: &[u64],
) -> Result<TransactChainContext> {
    ensure_schema(storage_path)?;

    let mut storage = open_storage(storage_path).context("open seeded database")?;

    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature.clone())?;
    let membership_blinding = encryption::derive_membership_blinding(&signature, network)?;

    storage.save_encryption_and_note_keypairs(
        user_address,
        TEST_KDF_DOMAIN,
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

        let index = u32::try_from(leaf_index).context("leaf index")?;
        let event_id = commitment_event_id(index, user_address);
        storage.save_events_batch(&ContractsEventData {
            events: vec![commitment_contract_event(
                event_id.clone(),
                pool_contract_id,
                &commitment,
                index,
                &encrypted_output,
            )?],
            cursor: format!("pool-cur-{leaf_index}"),
            latest_ledger: TEST_LEDGER,
        })?;

        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: event_id,
            commitment,
            index,
            encrypted_output,
            gvk_ciphertext: None,
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
        ASP_MEMBERSHIP_LEVELS,
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
        token_contract_id,
        asp_membership_contract_id,
        network,
    )
}

/// Garbles the `encrypted_output` of the seeded notes at `leaf_indices` and
/// drops the notes, as if the wallet had synced commitment events whose
/// ciphertexts were altered: it holds the commitments but never finds the
/// notes.
pub fn garble_seeded_outputs(storage_path: &Path, leaf_indices: &[u32]) -> Result<()> {
    let mut conn = open_connection(storage_path).context("open seeded database to garble")?;
    let tx = conn.transaction()?;
    for &leaf_index in leaf_indices {
        let (commitment, event_id, pool, length): (Field, String, String, i64) = tx
            .query_row(
                "SELECT pc.commitment, pc.event_id, c.address, length(pc.encrypted_output)
                 FROM pool_commitments pc
                 JOIN raw_contract_events r ON r.id = pc.event_id
                 JOIN contracts c ON c.contract_id = r.contract_id
                 WHERE pc.leaf_index = ?1",
                params![leaf_index],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .with_context(|| format!("no seeded note at leaf {leaf_index}"))?;
        let garbled = vec![0u8; usize::try_from(length)?];
        let event =
            commitment_contract_event(event_id.clone(), &pool, &commitment, leaf_index, &garbled)?;
        tx.execute(
            "DELETE FROM user_notes
             WHERE commitment_id = (SELECT id FROM pool_commitments WHERE leaf_index = ?1)",
            params![leaf_index],
        )?;
        tx.execute(
            "UPDATE pool_commitments SET encrypted_output = ?2 WHERE leaf_index = ?1",
            params![leaf_index, garbled],
        )?;
        tx.execute(
            "UPDATE raw_contract_events SET value = ?2 WHERE id = ?1",
            params![event_id, event.value],
        )?;
    }
    refold_event_chains(&tx)?;
    tx.commit()?;
    Ok(())
}

/// The ciphertexts of the seeded notes, by leaf index.
pub fn seeded_encrypted_outputs(storage_path: &Path) -> Result<Vec<Vec<u8>>> {
    let conn = open_connection(storage_path).context("open seeded database")?;
    let mut stmt =
        conn.prepare("SELECT encrypted_output FROM pool_commitments ORDER BY leaf_index")?;
    let outputs = stmt
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    Ok(outputs)
}

/// Folds every contract's raw events into its event chain again, as saving
/// them did, after a raw event was rewritten.
fn refold_event_chains(tx: &rusqlite::Transaction) -> Result<()> {
    let rows = {
        let mut stmt = tx.prepare(
            "SELECT id, contract_id, topics, value FROM raw_contract_events
             ORDER BY contract_id, ledger, id",
        )?;
        stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
    };
    tx.execute(
        "UPDATE raw_contract_events SET chain_count = NULL, chain_hash = NULL",
        [],
    )?;
    // Per contract: its chain so far, and whether an event stopped it, as an
    // event that does not fold stops saving's chain. The seed's ASP event
    // does.
    let mut current: Option<(i64, EventChain, bool)> = None;
    for (id, contract_id, topics, value) in rows {
        let (_, chain, stopped) = match &mut current {
            Some(state) if state.0 == contract_id => state,
            _ => current.insert((contract_id, EventChain::EMPTY, false)),
        };
        if *stopped {
            continue;
        }
        let topics: Vec<&str> = topics.split(',').collect();
        match chain.extend(&topics, &value) {
            Ok(next) => *chain = next,
            Err(_) => {
                *stopped = true;
                continue;
            }
        }
        tx.execute(
            "UPDATE raw_contract_events SET chain_count = ?2, chain_hash = ?3 WHERE id = ?1",
            params![id, i64::try_from(chain.count)?, chain.hash.as_slice()],
        )?;
    }
    Ok(())
}

/// The raw event id of the seeded commitment at `leaf_index`. Zero padding
/// makes the ids sort by leaf index, as an RPC's ids sort by emission.
fn commitment_event_id(leaf_index: u32, user_address: &str) -> String {
    format!("test-pool-commit-{leaf_index:010}-{user_address}")
}

/// A pool's `NewCommitmentEvent` as an RPC serves it: the commitment as a
/// topic after the event name, and a data map of the ciphertext and the leaf
/// index, in base64 `ScVal` XDR.
pub fn commitment_contract_event(
    id: String,
    pool_contract_id: &str,
    commitment: &Field,
    index: u32,
    encrypted_output: &[u8],
) -> Result<ContractEvent> {
    let b64 = |val: &ScVal| val.to_xdr_base64(Limits::none());
    let symbol = |name: &str| -> Result<ScVal> { Ok(ScVal::Symbol(ScSymbol(name.try_into()?))) };
    let be = commitment.to_be_bytes();
    let mut parts = be
        .chunks_exact(8)
        .map(|chunk| chunk.try_into().map(u64::from_be_bytes));
    let mut part = || -> Result<u64> { Ok(parts.next().context("a 32-byte commitment")??) };
    let commitment = ScVal::U256(UInt256Parts {
        hi_hi: part()?,
        hi_lo: part()?,
        lo_hi: part()?,
        lo_lo: part()?,
    });
    let data = ScVal::Map(Some(ScMap(
        vec![
            ScMapEntry {
                key: symbol("encrypted_output")?,
                val: ScVal::Bytes(ScBytes(encrypted_output.to_vec().try_into()?)),
            },
            ScMapEntry {
                key: symbol("index")?,
                val: ScVal::U32(index),
            },
        ]
        .try_into()?,
    )));
    Ok(ContractEvent {
        id,
        ledger: TEST_LEDGER,
        contract_id: pool_contract_id.to_string(),
        topics: vec![b64(&symbol("new_commitment_event")?)?, b64(&commitment)?],
        value: b64(&data)?,
    })
}

/// Simulate on-chain effects of a prepared step for offline multi-tx tests.
pub fn apply_proved_step(
    storage_path: &Path,
    pool_contract_id: &str,
    token_contract_id: &str,
    asp_membership_contract_id: &str,
    user_address: &str,
    network: &str,
    prepared: &stellar_private_payments::PreparedTransaction,
) -> Result<TransactChainContext> {
    use stellar_private_payments::zk::notes;

    let signature = test_derivation_signature();
    let (note_keypair, encryption_keypair) =
        encryption::derive_encryption_and_note_keypairs(signature.clone())?;

    let mut storage = open_storage(storage_path).context("open storage for apply step")?;
    let mut conn = open_connection(storage_path).context("open storage connection")?;
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
        token_contract_id,
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

        let event_id = commitment_event_id(leaf_index, user_address);
        storage.save_events_batch(&ContractsEventData {
            events: vec![commitment_contract_event(
                event_id.clone(),
                pool_contract_id,
                &commitment,
                leaf_index,
                encrypted_output,
            )?],
            cursor: format!("pool-apply-cur-{leaf_index}"),
            latest_ledger: TEST_LEDGER,
        })?;

        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: event_id,
            commitment,
            index: leaf_index,
            encrypted_output: encrypted_output.to_vec(),
            gvk_ciphertext: None,
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
        token_contract_id,
        asp_membership_contract_id,
        network,
    )
}

fn chain_snapshot_from_storage(
    storage_path: &Path,
    pool_contract_id: &str,
    token_contract_id: &str,
    asp_membership_contract_id: &str,
    _network: &str,
) -> Result<TransactChainContext> {
    let storage = open_storage(storage_path).context("open storage for chain snapshot")?;
    let signature = test_derivation_signature();
    let (note_keypair, _) = encryption::derive_encryption_and_note_keypairs(signature)?;
    let note_pubkey_field = Field::try_from_le_bytes(*note_keypair.public.as_ref())?;

    let pool_leaves = storage.get_pool_commitment_leaves_ordered(pool_contract_id)?;
    let pool_root = MerklePrefixTree::new(POOL_MERKLE_LEVELS, &pool_leaves)?
        .into_built()
        .root()?;
    let pool_next_index = u32::try_from(pool_leaves.len()).context("pool leaf count")?;

    let asp_leaves = storage.get_all_asp_membership_leaves_ordered(asp_membership_contract_id)?;
    let asp_membership_root = MerklePrefixTree::new(ASP_MEMBERSHIP_LEVELS, &asp_leaves)?
        .into_built()
        .root()?;

    Ok(TransactChainContext {
        pool_root,
        pool_next_index,
        pool_merkle_levels: POOL_MERKLE_LEVELS,
        token_contract_id: token_contract_id.to_string(),
        asp_membership_levels: ASP_MEMBERSHIP_LEVELS,
        asp_membership_root,
        asp_membership_contract_id: asp_membership_contract_id.to_string(),
        asp_membership_ledger: TEST_LEDGER,
        non_membership_proof: Some(AspNonMembershipProof {
            key: note_pubkey_field,
            old_key: Field::ZERO,
            old_value: Field::ZERO,
            is_old0: true,
            siblings: vec![Field::ZERO; SMT_DEPTH as usize],
            root: Field::ZERO,
        }),
        policy_flags: PolicyFlags::ALLOWLIST | PolicyFlags::BLOCKLIST,
        gvk_mode: GvkMode::Off,
        admin_view_key: None,
        deposits_paused: false,
        fee: NoteAmount::ZERO,
        minimum_deposit_amount: NoteAmount::ZERO,
        maximum_deposit_amount: ExtAmount::MAX,
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
    let mut conn = open_connection(storage_path).context("open seeded database for user_notes")?;
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
                account_id,
                commitment_id,
                expected_nullifier,
                blinding,
                amount
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(commitment_id) DO NOTHING",
            params![
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
