use anyhow::{Context, Result};
use rusqlite::{Connection, params, Error as SqlError, OptionalExtension};
use rusqlite_migration::{M, Migrations};
use types::{ContractEvent, Field, NewNullifierEvent, NewCommitmentEvent, PublicKeyEvent, LeafAddedEvent, EncryptionKeyPair, NoteKeyPair, NotePrivateKey, NotePublicKey, EncryptionPrivateKey,EncryptionPublicKey};

// shouldn't be changed for WASM OPFS otherwise the db will be lost
const DB_NAME: &str = "poolstellar.sqlite";

const MIGRATION_ARRAY: &[M] = &[M::up(include_str!("schema.sql"))];
const MIGRATIONS: Migrations = Migrations::from_slice(MIGRATION_ARRAY);

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn connect() -> Result<Self> {
        let mut conn = Connection::open(DB_NAME)?;
        MIGRATIONS.to_latest(&mut conn)?;

        conn.pragma_update(None, "foreign_keys", "ON")?;

        Ok(Self { conn })
    }

    pub fn save_events_batch(&mut self, data: &types::ContractsEventData) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO raw_contract_events (id, ledger, contract_id, topics, value)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO NOTHING"
            )?;

            for event in &data.events {
                    stmt.execute(params![
                        event.id,
                        event.ledger,
                        event.contract_id,
                        event.topics.join(","),
                        event.value
                    ])?;
            }

            tx.execute(
                "INSERT OR REPLACE INTO indexing_metadata (id, last_cursor) VALUES (1, ?1)",
                params![data.cursor],
            )?;

        }
        tx.commit()?;
        log::debug!("[STORAGE] saved {} events and cursor {}", data.events.len(), data.cursor);
        Ok(())
    }

    pub fn get_sync_metadata(&self) -> Result<Option<types::SyncMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT MAX(e.ledger), m.last_cursor
             FROM raw_contract_events e
             CROSS JOIN indexing_metadata m
             WHERE m.id = 1"
        )?;

        let status = stmt.query_row([], |row| {
            let ledger: Option<u32> = row.get(0)?;
            let cursor: Option<String> = row.get(1)?;
            match (ledger, cursor) {
                (Some(last_ledger), Some(cursor)) => Ok(Some(types::SyncMetadata{last_ledger, cursor})),
                _ => Ok(None),
            }
        })?;

        Ok(status)
    }

    pub fn get_user_keys(&self, address: &str) -> Result<Option<(NoteKeyPair, EncryptionKeyPair)>> {
        self.conn.query_row(
            "SELECT
                encryption_private_key,
                encryption_public_key,
                note_private_key,
                note_public_key
                FROM keypairs
                JOIN accounts ON keypairs.account_id = accounts.id
                WHERE accounts.address = ?1",
            params![address],
            |row| {
                let enc_priv: [u8; 32] = row.get(0)?;
                let enc_pub: [u8; 32] = row.get(1)?;
                let note_priv: [u8; 32] = row.get(2)?;
                let note_pub: [u8; 32] = row.get(3)?;

                Ok((
                    NoteKeyPair {
                        private: NotePrivateKey(note_priv),
                        public: NotePublicKey(note_pub),
                    },
                    EncryptionKeyPair {
                        private: EncryptionPrivateKey(enc_priv),
                        public: EncryptionPublicKey(enc_pub),
                    },
                ))
            },
        )
        .optional()
        .context(format!("Failed to fetch keys for account: {}", address))
    }

    pub fn save_encryption_and_note_keypairs(
        &mut self,
        account_address: &str,
        note_keypair: &NoteKeyPair,
        encryption_keypair: &EncryptionKeyPair,
    ) -> Result<()> {
        let tx = self.conn.transaction().context("failed to start transaction")?;

        let account_id = Self::get_or_create_account(&tx, account_address)?;

        tx.execute(
            "INSERT INTO keypairs (
                encryption_private_key,
                encryption_public_key,
                note_private_key,
                note_public_key,
                account_id
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &encryption_keypair.private.0,
                &encryption_keypair.public.0,
                &note_keypair.private.0,
                &note_keypair.public.0,
                account_id,
            ],
        )
        .context("failed to insert keypairs")?;
        tx.commit().context("failed to commit transaction")?;
        log::debug!("[STORAGE] saved new keypairs for the account {}", account_address);
        Ok(())
    }

    /// Internal helper to handle the "Get or Create" logic for accounts
    fn get_or_create_account(tx: &rusqlite::Transaction, address: &str) -> Result<i64> {
        tx.execute(
            "INSERT OR IGNORE INTO accounts (address) VALUES (?1)",
            params![address],
        ).context("failed to insert account")?;

        let id: i64 = tx.query_row(
            "SELECT id FROM accounts WHERE address = ?1",
            params![address],
            |row| row.get(0),
        ).context("failed to fetch account id")?;

        Ok(id)
    }

    /// Returns $limit public keys ordered by ledger descending.
    /// for an address book
    pub fn get_recent_public_keys(&self, limit: u32) -> Result<Vec<types::PublicKeyEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, encryption_key, note_key, public_key, ledger
                     FROM registered_public_keys ORDER BY ledger DESC LIMIT ?1",
            )
            .context("prepare get_all_public_keys")?;
        stmt.query_map([limit], map_public_key_entry)
            .context("get_all_public_keys")?
            .collect::<Result<Vec<_>, _>>()
            .context("get_all_public_keys collect")
    }

    /// Batch upsert for spent nullifiers
    pub fn save_nullifier_events_batch(&mut self, events: &Vec<NewNullifierEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO pool_nullifiers (nullifier, event_id)
                    VALUES (?1, ?2)
                    ON CONFLICT(nullifier) DO NOTHING"
            )?;

            for event in events {
                stmt.execute(params![event.nullifier, event.id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Batch upsert for Merkle tree commitments
    pub fn save_commitment_events_batch(&mut self, events: &Vec<NewCommitmentEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO pool_commitments (commitment, leaf_index, encrypted_output, event_id)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(commitment) DO NOTHING"
            )?;

            for event in events {
                stmt.execute(params![event.commitment, event.index, event.encrypted_output, event.id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Batch upsert for Public Keys (Address owner and BLOB keys)
    pub fn save_public_key_events_batch(&mut self, events: &Vec<PublicKeyEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO public_keys (owner, encryption_key, note_key, event_id)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(owner) DO NOTHING"
            )?;

            for event in events {
                stmt.execute(params![
                    event.owner,
                    event.encryption_key.0,
                    event.note_key.0,
                    event.id
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Batch upsert for ASP Membership Leaves
    pub fn save_leaf_added_events_batch(&mut self, events: &Vec<LeafAddedEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO asp_membership_leaves (leaf_index, leaf, root, event_id)
                    VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(leaf_index) DO NOTHING"
            )?;

            for event in events {
                stmt.execute(params![event.index, event.leaf, event.root, event.id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Checks whether ASP membership data is usable for proving at the current network tip.
    ///
    /// Returns:
    /// - `Ok(Some(user_leaf_index))`  if:
    ///   1) `user_leaf` is present in `asp_membership_leaves`, and
    ///   2) `current_root` equals the last stored root in `asp_membership_leaves`, and
    ///   3) `current_ledger` equals the last stored ledger in the DB.
    /// - `Ok(None)` if the DB is behind the chain tip (`current_ledger` is ahead of the
    ///   last stored ledger), meaning the caller should sync more events.
    /// - `Err(_)` if `current_ledger == last_db_ledger` but the user leaf is missing, or if
    ///   roots/ledgers are inconsistent (indicates corruption or mismatched networks).
    pub fn check_asp_membership_precondition(
        &self,
        user_leaf: &Field,
        current_root: &Field,
        current_ledger: u32,
    ) -> Result<Option<u32>> {
        // Get the last stored root and its ledger by joining through the raw events table.
        let mut stmt = self.conn.prepare(
            "SELECT l.root, r.ledger
             FROM asp_membership_leaves l
             JOIN raw_contract_events r ON r.id = l.event_id
             ORDER BY l.leaf_index DESC
             LIMIT 1",
        )?;

        let last: Option<(Field, u32)> = stmt
            .query_row([], |row| {
                let root: Field = row.get(0)?;
                let ledger_i64: i64 = row.get(1)?;
                let ledger = col_u32(ledger_i64, 1)?;
                Ok((root, ledger))
            })
            .optional()
            .context("Failed to query asp_membership_leaves last root/ledger")?;

        let Some((last_root, last_ledger)) = last else {
            // No local membership data: treat as "need sync".
            return Ok(None);
        };

        if current_ledger > last_ledger {
            return Ok(None);
        }

        if current_ledger < last_ledger {
            anyhow::bail!(
                "asp membership storage is ahead of chain tip: local={}, chain={}",
                last_ledger,
                current_ledger
            );
        }

        // current_ledger == last_ledger: require root match and leaf existence.
        if *current_root != last_root {
            anyhow::bail!("asp membership root mismatch at ledger {}", current_ledger);
        }

        let mut stmt = self.conn.prepare(
            "SELECT leaf_index
             FROM asp_membership_leaves
             WHERE leaf = ?1
             LIMIT 1",
        )?;

        let user_leaf_index: Option<u32> = stmt
            .query_row(params![user_leaf], |row| row.get(0))
            .optional()
            .context("Failed to query asp_membership_leaves user leaf existence")?;

        if user_leaf_index.is_some() {
            return Ok(user_leaf_index);
        }

        anyhow::bail!(
            "asp membership precondition failed at ledger {}: local state is out of sync with the chain",
            current_ledger
        );
    }

    // TODO ideally we should return an iterator here
    /// Fetch all ASP membership leaves ordered by index (0..N-1), returning the leaf list
    /// plus the last stored root (root after the last insertion).
    ///
    /// Errors if there are gaps/out-of-order indices, because Merkle reconstruction would
    /// be ambiguous/incorrect.
    pub fn get_all_asp_membership_leaves_ordered(&self) -> Result<Vec<Field>> {
        let mut stmt = self.conn.prepare(
            "SELECT leaf_index, leaf
             FROM asp_membership_leaves
             ORDER BY leaf_index ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            let idx: i64 = row.get(0)?;
            let idx = col_u32(idx, 0)?;
            let leaf: Field = row.get(1)?;
            Ok((idx, leaf))
        })?;

        let mut leaves: Vec<Field> = Vec::new();
        let mut expected_index: u32 = 0;

        for row in rows {
            let (idx, leaf) = row?;
            if idx != expected_index {
                anyhow::bail!(
                    "asp_membership_leaves gap/out-of-order: expected index {}, got {}",
                    expected_index,
                    idx
                );
            }
            leaves.push(leaf);
            expected_index = expected_index
                .checked_add(1)
                .context("asp_membership_leaves index overflow")?;
        }

        Ok(leaves)
    }

    /// Unprocessed raw events fetch
    pub fn get_unprocessed_events(&self, limit: u32) -> Result<Vec<ContractEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.ledger, r.contract_id, r.topics, r.value
                FROM raw_contract_events r
                LEFT JOIN pool_nullifiers n ON r.id = n.event_id
                LEFT JOIN pool_commitments c ON r.id = c.event_id
                LEFT JOIN public_keys p ON r.id = p.event_id
                LEFT JOIN asp_membership_leaves l ON r.id = l.event_id
                WHERE n.event_id IS NULL
                AND c.event_id IS NULL
                AND p.event_id IS NULL
                AND l.event_id IS NULL
                ORDER BY r.ledger ASC, r.id ASC
                LIMIT ?1"
        )?;

        let event_iter = stmt.query_map(params![limit], |row| {
            let topics_str: String = row.get(3)?;
            Ok(ContractEvent {
                id: row.get(0)?,
                ledger: row.get(1)?,
                contract_id: row.get(2)?,
                // Split the comma-separated topics back into a Vec
                topics: topics_str.split(',').map(|s| s.to_string()).collect(),
                value: row.get(4)?,
            })
        })?;

        let mut events = Vec::new();
        for event in event_iter {
            events.push(event?);
        }

        Ok(events)
    }
}

// ---------------------------------------------------------------------------
// Row-mapping helpers
// ---------------------------------------------------------------------------

/// Converts an `i64` SQLite column to `u32`, returning a rusqlite error on
/// overflow.
fn col_u32(val: i64, col: usize) -> Result<u32, SqlError> {
    u32::try_from(val).map_err(|_| SqlError::IntegralValueOutOfRange(col, val))
}

fn map_public_key_entry(row: &rusqlite::Row<'_>) -> Result<types::PublicKeyEntry, SqlError> {
    Ok(types::PublicKeyEntry {
        address: row.get(0)?,
        encryption_key: EncryptionPublicKey(row.get(1)?),
        note_key: NotePublicKey(row.get(2)?),
        ledger: col_u32(row.get::<_, i64>(4)?, 4)?,
    })
}
