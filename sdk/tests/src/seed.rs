//! Seed a migrated SQLite wallet for integration tests.

use std::path::Path;

use anyhow::Context;
use rusqlite::{Connection, Transaction, params};
use stellar_private_payments_sdk::storage::Storage;
use types::{Field, NoteAmount};

/// Open (or create) `path` with schema migrations applied
pub fn ensure_schema(storage_path: &Path) -> anyhow::Result<()> {
    let _storage = Storage::connect_file(storage_path).context("apply storage migrations")?;
    Ok(())
}

/// Insert unspent notes into provided DB
pub fn seed_notes(
    storage_path: &Path,
    pool_contract_id: &str,
    user_address: &str,
    notes: &[(Field, NoteAmount)],
) -> anyhow::Result<()> {
    ensure_schema(storage_path)?;

    let mut conn = Connection::open(storage_path).context("open seeded database")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    let tx = conn.transaction()?;
    let pool_contract_id = get_or_create_contract_id(&tx, pool_contract_id)?;
    let account_id = get_or_create_account_id(&tx, user_address)?;

    for (leaf_index, (commitment, amount)) in notes.iter().enumerate() {
        let event_id = format!("test-event-{leaf_index}-{user_address}");
        tx.execute(
            "INSERT INTO raw_contract_events (id, ledger, contract_id, topics, value)
             VALUES (?1, 1, ?2, 'test', 'dGVzdA==')
             ON CONFLICT(id) DO NOTHING",
            params![event_id, pool_contract_id],
        )?;

        tx.execute(
            "INSERT INTO pool_commitments (commitment, leaf_index, encrypted_output, event_id)
             VALUES (?1, ?2, X'00', ?3)
             ON CONFLICT(commitment) DO NOTHING",
            params![
                commitment,
                u32::try_from(leaf_index).context("leaf index")?,
                event_id
            ],
        )?;

        let commitment_id: i64 = tx.query_row(
            "SELECT id FROM pool_commitments WHERE commitment = ?1",
            params![commitment],
            |row| row.get(0),
        )?;

        let mut blinding = [0u8; 32];
        blinding[0] = u8::try_from(leaf_index).context("blinding seed")? + 1;
        let mut expected_nullifier = [0u8; 32];
        expected_nullifier[0] = u8::try_from(leaf_index).context("nullifier seed")? + 2;

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
                Field::try_from_le_bytes(expected_nullifier)?,
                Field::try_from_le_bytes(blinding)?,
                amount.to_string(),
            ],
        )?;
    }

    tx.commit()?;
    Ok(())
}

fn get_or_create_contract_id(tx: &Transaction<'_>, address: &str) -> anyhow::Result<i64> {
    tx.query_row(
        "INSERT INTO contracts (address)
         VALUES (?1)
         ON CONFLICT(address) DO UPDATE SET address = excluded.address
         RETURNING contract_id",
        params![address],
        |row| row.get(0),
    )
    .context("failed to get or create contract id")
}

fn get_or_create_account_id(tx: &Transaction<'_>, address: &str) -> anyhow::Result<i64> {
    tx.query_row(
        "INSERT INTO accounts (address)
         VALUES (?1)
         ON CONFLICT(address) DO UPDATE SET address = excluded.address
         RETURNING id",
        params![address],
        |row| row.get(0),
    )
    .context("failed to get or create account id")
}
