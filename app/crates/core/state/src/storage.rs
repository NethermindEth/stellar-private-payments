use anyhow::{Context, Result};
use rusqlite::{Connection, params, Error as SqlError, OptionalExtension};
use rusqlite_migration::{M, Migrations};
use types::{
    AspMembershipSync, ContractEvent, EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey,
    Field, LeafAddedEvent, NewCommitmentEvent, NewNullifierEvent, NoteAmount, NoteKeyPair,
    NotePrivateKey, NotePublicKey, PublicKeyEvent,
};

// shouldn't be changed for WASM OPFS otherwise the db will be lost
const DB_NAME: &str = "poolstellar.sqlite";

const MIGRATION_ARRAY: &[M] = &[M::up(include_str!("schema.sql"))];
const MIGRATIONS: Migrations = Migrations::from_slice(MIGRATION_ARRAY);

pub struct Storage {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct AccountKeys {
    pub account_id: i64,
    pub note_keypair: NoteKeyPair,
    pub encryption_keypair: EncryptionKeyPair,
}

#[derive(Debug, Clone)]
pub struct PoolCommitmentRow {
    pub commitment_id: i64,
    pub commitment: Field,
    pub leaf_index: u32,
    pub encrypted_output: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DerivedUserNoteRow {
    pub amount: NoteAmount,
    pub blinding: Field,
    pub expected_nullifier: Field,
}

pub type DeriveNoteFn<'a> =
    dyn FnMut(&AccountKeys, &PoolCommitmentRow) -> Result<Option<DerivedUserNoteRow>> + 'a;

impl Storage {
    pub fn connect() -> Result<Self> {
        Self::connect_with_connection(Connection::open(DB_NAME)?)
    }

    fn connect_with_connection(mut conn: Connection) -> Result<Self> {
        MIGRATIONS.to_latest(&mut conn)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(Self { conn })
    }

    #[cfg(test)]
    pub fn connect_in_memory() -> Result<Self> {
        Self::connect_with_connection(Connection::open_in_memory()?)
    }

    pub fn save_events_batch(&mut self, data: &types::ContractsEventData) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO raw_contract_events (id, ledger, contract_id, topics, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)
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
                let enc_priv: EncryptionPrivateKey = row.get(0)?;
                let enc_pub: EncryptionPublicKey = row.get(1)?;
                let note_priv: NotePrivateKey = row.get(2)?;
                let note_pub: NotePublicKey = row.get(3)?;

                Ok((
                    NoteKeyPair {
                        private: note_priv,
                        public: note_pub,
                    },
                    EncryptionKeyPair {
                        private: enc_priv,
                        public: enc_pub,
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
                &encryption_keypair.private,
                &encryption_keypair.public,
                &note_keypair.private,
                &note_keypair.public,
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
                "SELECT p.owner, p.encryption_key, p.note_key, r.ledger
                 FROM public_keys p
                 JOIN raw_contract_events r ON r.id = p.event_id
                 ORDER BY r.ledger DESC
                 LIMIT ?1",
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
                    event.encryption_key,
                    event.note_key,
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
    ) -> Result<AspMembershipSync> {
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
            return Ok(AspMembershipSync::RegisterAtASP);
        };

        if current_ledger > last_ledger {
            return Ok(AspMembershipSync::SyncRequired);
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

        if let Some(user_leaf_index) = user_leaf_index {
            return Ok(AspMembershipSync::UserIndex(user_leaf_index));
        }

        Ok(AspMembershipSync::RegisterAtASP)
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

    fn get_accounts_with_latest_keypairs(&self) -> Result<Vec<AccountKeys>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                a.id,
                k.encryption_private_key,
                k.encryption_public_key,
                k.note_private_key,
                k.note_public_key
             FROM accounts a
             JOIN (
                SELECT account_id, MAX(id) AS max_id
                FROM keypairs
                WHERE account_id IS NOT NULL
                GROUP BY account_id
             ) latest ON latest.account_id = a.id
             JOIN keypairs k ON k.id = latest.max_id
             ORDER BY a.id ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            let account_id: i64 = row.get(0)?;
            let enc_priv: EncryptionPrivateKey = row.get(1)?;
            let enc_pub: EncryptionPublicKey = row.get(2)?;
            let note_priv: NotePrivateKey = row.get(3)?;
            let note_pub: NotePublicKey = row.get(4)?;

            Ok(AccountKeys {
                account_id,
                note_keypair: NoteKeyPair {
                    private: note_priv,
                    public: note_pub,
                },
                encryption_keypair: EncryptionKeyPair {
                    private: enc_priv,
                    public: enc_pub,
                },
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Scan pool commitments and insert decryptable notes into `user_notes`.
    ///
    /// Progress is tracked per-account in `account_commitment_scan`.
    pub fn scan_commitments_for_user_notes(
        &mut self,
        total_limit: u32,
        derive: &mut DeriveNoteFn<'_>,
    ) -> Result<bool> {
        let accounts = self.get_accounts_with_latest_keypairs()?;
        if accounts.is_empty() || total_limit == 0 {
            return Ok(false);
        }

        let tx = self.conn.transaction()?;

        // Ensure scheduler row exists.
        tx.execute(
            "INSERT OR IGNORE INTO notes_scan_scheduler (id, next_account_offset)
             VALUES (1, 0)",
            [],
        )?;

        let n = accounts.len();
        let n_i64 = i64::try_from(n).expect("accounts len fits i64");
        let mut offset: i64 = tx.query_row(
            "SELECT next_account_offset FROM notes_scan_scheduler WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        offset = offset.rem_euclid(n_i64);
        let offset_usize = usize::try_from(offset).expect("offset fits usize");

        // Histogram allocation: `total_limit` tokens distributed in RR order from `offset`.
        let mut counts: Vec<u32> = vec![0; n];
        for i in 0..total_limit {
            let idx = (offset_usize + usize::try_from(i).expect("u32 fits usize")) % n;
            counts[idx] = counts[idx].saturating_add(1);
        }

        // Ensure scan cursors exist for all accounts.
        for a in &accounts {
            tx.execute(
                "INSERT OR IGNORE INTO account_commitment_scan (account_id, last_commitment_id)
                 VALUES (?1, 0)",
                params![a.account_id],
            )?;
        }

        let mut did_progress = false;

        for (idx, quota) in counts.into_iter().enumerate() {
            if quota == 0 {
                continue;
            }
            let account = &accounts[idx];

            let last_commitment_id: i64 = tx.query_row(
                "SELECT last_commitment_id
                 FROM account_commitment_scan
                 WHERE account_id = ?1",
                params![account.account_id],
                |row| row.get(0),
            )?;

            let commitments: Vec<PoolCommitmentRow> = {
                let mut stmt = tx.prepare(
                    "SELECT id, commitment, leaf_index, encrypted_output
                     FROM pool_commitments
                     WHERE id > ?1
                     ORDER BY id ASC
                     LIMIT ?2",
                )?;

                let rows = stmt.query_map(params![last_commitment_id, quota], |row| {
                    let commitment_id: i64 = row.get(0)?;
                    let commitment: Field = row.get(1)?;
                    let leaf_index_i64: i64 = row.get(2)?;
                    let leaf_index = col_u32(leaf_index_i64, 2)?;
                    let encrypted_output: Vec<u8> = row.get(3)?;
                    Ok(PoolCommitmentRow {
                        commitment_id,
                        commitment,
                        leaf_index,
                        encrypted_output,
                    })
                })?;

                let mut out = Vec::new();
                for r in rows {
                    out.push(r?);
                }
                out
            };

            let mut max_scanned_id = last_commitment_id;
            for row in commitments {
                if row.commitment_id > max_scanned_id {
                    max_scanned_id = row.commitment_id;
                }

                let Some(derived) = derive(account, &row)? else {
                    continue;
                };

                let nullifier_id: Option<i64> = tx
                    .query_row(
                        "SELECT id FROM pool_nullifiers WHERE nullifier = ?1 LIMIT 1",
                        params![derived.expected_nullifier],
                        |r| r.get(0),
                    )
                    .optional()?;

                tx.execute(
                    "INSERT OR IGNORE INTO user_notes (
                        id,
                        account_id,
                        commitment_id,
                        nullifier_id,
                        expected_nullifier,
                        blinding,
                        amount
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        row.commitment,
                        account.account_id,
                        row.commitment_id,
                        nullifier_id,
                        derived.expected_nullifier,
                        derived.blinding,
                        derived.amount
                    ],
                )?;
            }

            if max_scanned_id > last_commitment_id {
                tx.execute(
                    "UPDATE account_commitment_scan
                     SET last_commitment_id = ?1
                     WHERE account_id = ?2",
                    params![max_scanned_id, account.account_id],
                )?;
                did_progress = true;
            }
        }

        // Advance scheduler offset to continue after the last assigned token.
        let step = i64::from(total_limit).rem_euclid(n_i64);
        let next_offset = (offset + step).rem_euclid(n_i64);
        tx.execute(
            "UPDATE notes_scan_scheduler
             SET next_account_offset = ?1
             WHERE id = 1",
            params![next_offset],
        )?;

        // If there's remaining work for any account, keep the processing loop alive.
        let has_pending: bool = tx
            .query_row(
                "SELECT 1
                 FROM account_commitment_scan s
                 WHERE EXISTS (SELECT 1 FROM keypairs k WHERE k.account_id = s.account_id)
                   AND EXISTS (SELECT 1 FROM pool_commitments c WHERE c.id > s.last_commitment_id)
                 LIMIT 1",
                [],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        tx.commit()?;
        Ok(did_progress || has_pending)
    }

    /// Reconcile new pool nullifiers against `user_notes.expected_nullifier`, updating
    /// `user_notes.nullifier_id` for matching notes.
    pub fn reconcile_nullifiers(&mut self, limit: u32) -> Result<bool> {
        let tx = self.conn.transaction()?;

        let last_nullifier_id: i64 = tx.query_row(
            "SELECT last_nullifier_id FROM nullifier_scan_state WHERE id = 1",
            [],
            |row| row.get(0),
        )?;

        let nullifiers: Vec<(i64, Field)> = {
            let mut stmt = tx.prepare(
                "SELECT id, nullifier
                 FROM pool_nullifiers
                 WHERE id > ?1
                 ORDER BY id ASC
                 LIMIT ?2",
            )?;

            let rows = stmt.query_map(params![last_nullifier_id, limit], |row| {
                let id: i64 = row.get(0)?;
                let nullifier: Field = row.get(1)?;
                Ok((id, nullifier))
            })?;

            let mut out = Vec::new();
            for r in rows {
                out.push(r?);
            }
            out
        };

        let mut max_id = last_nullifier_id;
        let mut did_any = false;

        for (nullifier_id, nullifier) in nullifiers {
            did_any = true;
            if nullifier_id > max_id {
                max_id = nullifier_id;
            }

            tx.execute(
                "UPDATE user_notes
                 SET nullifier_id = ?1
                 WHERE nullifier_id IS NULL
                   AND expected_nullifier = ?2",
                params![nullifier_id, nullifier],
            )?;
        }

        if max_id > last_nullifier_id {
            tx.execute(
                "UPDATE nullifier_scan_state SET last_nullifier_id = ?1 WHERE id = 1",
                params![max_id],
            )?;
        }

        tx.commit()?;
        Ok(did_any)
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
        encryption_key: row.get(1)?,
        note_key: row.get(2)?,
        ledger: col_u32(row.get::<_, i64>(3)?, 3)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover::{crypto, encryption};
    use types::{
        ContractEvent, ContractsEventData, EncryptionPublicKey, EncryptionSignature, NoteAmount,
        NotePublicKey, PublicKeyEvent, SpendingSignature,
    };

    fn dummy_event(id: &str) -> ContractEvent {
        ContractEvent {
            id: id.to_string(),
            ledger: 1,
            contract_id: "CPOOL".to_string(),
            topics: vec!["dummy".to_string()],
            value: "dummy".to_string(),
        }
    }

    #[test]
    fn get_recent_public_keys_reads_public_keys_with_ledger() -> Result<()> {
        let mut storage = Storage::connect_in_memory()?;

        let event_id = "pk_event_1";
        storage.save_events_batch(&ContractsEventData {
            cursor: "cursor".to_string(),
            events: vec![ContractEvent {
                id: event_id.to_string(),
                ledger: 42,
                contract_id: "CPOOL".to_string(),
                topics: vec!["pk".to_string()],
                value: "dummy".to_string(),
            }],
        })?;

        storage.save_public_key_events_batch(&vec![PublicKeyEvent {
            id: event_id.to_string(),
            owner: "GTESTOWNER".to_string(),
            encryption_key: EncryptionPublicKey([1u8; 32]),
            note_key: NotePublicKey([2u8; 32]),
        }])?;

        let list = storage.get_recent_public_keys(1)?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].address, "GTESTOWNER");
        assert_eq!(list[0].ledger, 42);
        Ok(())
    }

    #[test]
    fn scan_commitments_and_reconcile_nullifiers() -> Result<()> {
        let mut storage = Storage::connect_in_memory()?;

        // Create an account with keypairs.
        let spending_sig = SpendingSignature(vec![1u8; 64]);
        let encryption_sig = EncryptionSignature(vec![2u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(spending_sig, encryption_sig)?;
        storage.save_encryption_and_note_keypairs("GTESTACCOUNT", &note_keypair, &enc_keypair)?;

        let account_id: i64 = storage.conn.query_row(
            "SELECT id FROM accounts WHERE address = ?1",
            params!["GTESTACCOUNT"],
            |row| row.get(0),
        )?;

        // Build a commitment + encrypted output addressed to the account.
        let amount = NoteAmount(5);
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = 7;
        let blinding = Field::try_from_le_bytes(blinding_le)?;

        let amount_field_le = Field::from(amount).to_le_bytes();
        let commitment_le = crypto::compute_commitment(
            &amount_field_le,
            note_keypair.public.as_ref(),
            &blinding.to_le_bytes(),
        )?;
        let commitment_le: [u8; 32] = commitment_le
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("commitment: expected 32 bytes, got {}", v.len()))?;
        let commitment = Field::try_from_le_bytes(commitment_le)?;

        let encrypted_output = encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;

        // Insert the raw event + the parsed pool commitment row.
        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-commit")],
            cursor: "cur".to_string(),
        })?;
        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: "evt-commit".to_string(),
            commitment,
            index: 3,
            encrypted_output: encrypted_output.clone(),
        }])?;

        // Scan commitments -> user_notes.
        let mut derive = |account: &AccountKeys,
                          row: &PoolCommitmentRow|
         -> Result<Option<DerivedUserNoteRow>> {
            let opt = prover::notes::try_decrypt_and_derive_user_note(
                &account.note_keypair,
                &account.encryption_keypair.private,
                &row.commitment,
                row.leaf_index,
                &row.encrypted_output,
            )?;
            Ok(opt.map(|d| DerivedUserNoteRow {
                amount: d.amount,
                blinding: d.blinding,
                expected_nullifier: d.expected_nullifier,
            }))
        };
        assert!(storage.scan_commitments_for_user_notes(100, &mut derive)?);

        let note_count: i64 = storage
            .conn
            .query_row("SELECT COUNT(*) FROM user_notes", [], |row| row.get(0))?;
        assert_eq!(note_count, 1);

        let scanned: i64 = storage.conn.query_row(
            "SELECT last_commitment_id FROM account_commitment_scan WHERE account_id = ?1",
            params![account_id],
            |row| row.get(0),
        )?;
        assert!(scanned > 0);

        // Insert a matching nullifier event.
        let leaf_index: u32 = 3;
        let mut path_indices_le = [0u8; 32];
        path_indices_le[..8].copy_from_slice(&(u64::from(leaf_index)).to_le_bytes());
        let signature = crypto::compute_signature(&note_keypair.private.0, &commitment.to_le_bytes(), &path_indices_le)?;
        let nullifier_le = crypto::compute_nullifier(&commitment.to_le_bytes(), &path_indices_le, &signature)?;
        let nullifier_le: [u8; 32] = nullifier_le
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("nullifier: expected 32 bytes, got {}", v.len()))?;
        let nullifier = Field::try_from_le_bytes(nullifier_le)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-null")],
            cursor: "cur2".to_string(),
        })?;
        storage.save_nullifier_events_batch(&vec![NewNullifierEvent {
            id: "evt-null".to_string(),
            nullifier,
        }])?;

        assert!(storage.reconcile_nullifiers(100)?);

        let nullifier_id: Option<i64> = storage.conn.query_row(
            "SELECT nullifier_id FROM user_notes WHERE account_id = ?1",
            params![account_id],
            |row| row.get(0),
        )?;
        assert!(nullifier_id.is_some());

        Ok(())
    }
}
