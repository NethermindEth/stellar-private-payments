use crate::disclaimer::{CURRENT_DISCLAIMER_HASH_HEX, CURRENT_DISCLAIMER_TEXT_MD};
use anyhow::{Context, Result};
use rusqlite::{Connection, Error as SqlError, OptionalExtension, params};
use rusqlite_migration::{M, Migrations};
use types::{
    AspMembershipSync, ContractEvent, EncryptionKeyPair, EncryptionPrivateKey, EncryptionPublicKey,
    Field, LeafAddedEvent, NewCommitmentEvent, NewNullifierEvent, NoteAmount, NoteKeyPair,
    NotePrivateKey, NotePublicKey, PoolLedgerActivity, PublicKeyEvent, UserNoteSummary,
};

// shouldn't be changed for WASM OPFS otherwise the db will be lost
const DB_NAME: &str = "poolstellar.sqlite";

const MIGRATION_ARRAY: &[M] = &[M::up(include_str!("schema.sql"))];
const MIGRATIONS: Migrations = Migrations::from_slice(MIGRATION_ARRAY);

pub struct Storage {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct DisclaimerState {
    pub disclaimer_text_md: String,
    pub disclaimer_hash_hex: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootnodeConfig {
    pub enabled: bool,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct AccountKeys {
    pub account_id: i64,
    pub note_keypair: NoteKeyPair,
    pub encryption_keypair: EncryptionKeyPair,
    pub membership_blinding: Field,
}

#[derive(Debug, Clone)]
pub struct StoredUserKeys {
    pub note_keypair: NoteKeyPair,
    pub encryption_keypair: EncryptionKeyPair,
    pub membership_blinding: Field,
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

    pub fn save_events_batch(&mut self, data: &types::ContractsEventData) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO raw_contract_events (id, ledger, contract_id, topics, value)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO NOTHING",
            )?;

            for event in &data.events {
                let event_contract_id = Self::get_or_create_contract_id(&tx, &event.contract_id)?;
                stmt.execute(params![
                    event.id,
                    event.ledger,
                    event_contract_id,
                    event.topics.join(","),
                    event.value
                ])?;
            }
        }
        tx.commit()?;
        log::debug!(
            "[STORAGE] saved {} events and cursor {} (latest_ledger={})",
            data.events.len(),
            data.cursor,
            data.latest_ledger
        );
        Ok(())
    }

    pub fn save_sync_progress(
        &mut self,
        metadata: &[types::SyncMetadata],
        fully_indexed: bool,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        for entry in metadata {
            let contract_id = Self::get_or_create_contract_id(&tx, &entry.contract_id)?;
            tx.execute(
                "INSERT INTO indexing_metadata (contract_id, last_cursor, last_indexed_ledger, last_fully_indexed_ledger)
                 VALUES (?1, ?2, ?3, 0)
                 ON CONFLICT(contract_id) DO NOTHING",
                params![contract_id, entry.cursor, entry.last_indexed_ledger],
            )?;

            if fully_indexed {
                tx.execute(
                    "UPDATE indexing_metadata
                     SET last_cursor = ?2, last_indexed_ledger = ?3, last_fully_indexed_ledger = ?3
                     WHERE contract_id = ?1",
                    params![contract_id, entry.cursor, entry.last_indexed_ledger],
                )?;
            } else {
                tx.execute(
                    "UPDATE indexing_metadata
                     SET last_cursor = ?2, last_indexed_ledger = ?3
                     WHERE contract_id = ?1",
                    params![contract_id, entry.cursor, entry.last_indexed_ledger],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Clears stored RPC cursors so the indexer restarts pagination by ledger.
    pub fn clear_indexing_cursors(&mut self) -> Result<()> {
        self.conn
            .execute("UPDATE indexing_metadata SET last_cursor = NULL", [])
            .context("failed to clear indexing cursors")?;
        Ok(())
    }

    pub fn get_sync_metadata(&self) -> Result<Vec<types::SyncMetadata>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.address, m.last_indexed_ledger, m.last_fully_indexed_ledger, m.last_cursor
             FROM indexing_metadata m
             JOIN contracts c ON c.contract_id = m.contract_id
             ORDER BY m.contract_id",
        )?;

        let rows = stmt.query_map([], |row| {
            let contract_id: String = row.get(0)?;
            let indexed_ledger_i64: i64 = row.get(1)?;
            let last_indexed_ledger = col_u32(indexed_ledger_i64, 1)?;
            let fully_indexed_ledger_i64: i64 = row.get(2)?;
            let last_fully_indexed_ledger = col_u32(fully_indexed_ledger_i64, 2)?;
            let cursor: Option<String> = row.get(3)?;
            Ok(types::SyncMetadata {
                contract_id,
                last_indexed_ledger,
                last_fully_indexed_ledger,
                cursor: cursor.unwrap_or_default(),
            })
        })?;

        let mut metadata = Vec::new();
        for row in rows {
            metadata.push(row?);
        }

        Ok(metadata)
    }

    pub fn get_user_keys(&self, address: &str) -> Result<Option<StoredUserKeys>> {
        self.conn
            .query_row(
                "SELECT
                encryption_private_key,
                encryption_public_key,
                note_private_key,
                note_public_key,
                membership_blinding
                FROM keypairs
                JOIN accounts ON keypairs.account_id = accounts.id
                WHERE accounts.address = ?1
                ORDER BY keypairs.id DESC
                LIMIT 1",
                params![address],
                |row| {
                    let enc_priv: EncryptionPrivateKey = row.get(0)?;
                    let enc_pub: EncryptionPublicKey = row.get(1)?;
                    let note_priv: NotePrivateKey = row.get(2)?;
                    let note_pub: NotePublicKey = row.get(3)?;
                    let membership_blinding: Field = row.get(4)?;

                    Ok(StoredUserKeys {
                        note_keypair: NoteKeyPair {
                            private: note_priv,
                            public: note_pub,
                        },
                        encryption_keypair: EncryptionKeyPair {
                            private: enc_priv,
                            public: enc_pub,
                        },
                        membership_blinding,
                    })
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
        membership_blinding: &Field,
    ) -> Result<()> {
        let tx = self
            .conn
            .transaction()
            .context("failed to start transaction")?;

        let account_id = Self::get_or_create_account(&tx, account_address)?;

        tx.execute(
            "INSERT INTO keypairs (
                encryption_private_key,
                encryption_public_key,
                note_private_key,
                note_public_key,
                membership_blinding,
                account_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &encryption_keypair.private,
                &encryption_keypair.public,
                &note_keypair.private,
                &note_keypair.public,
                membership_blinding,
                account_id,
            ],
        )
        .context("failed to insert keypairs")?;
        tx.commit().context("failed to commit transaction")?;
        log::debug!(
            "[STORAGE] saved new keypairs for the account {}",
            account_address
        );
        Ok(())
    }

    pub fn get_disclaimer_state(&mut self, address: &str) -> Result<DisclaimerState> {
        let tx = self
            .conn
            .transaction()
            .context("failed to start transaction")?;
        let account_id = Self::get_or_create_account(&tx, address)?;

        let accepted: Option<i64> = tx
            .query_row(
                "SELECT 1
                 FROM disclaimer_acceptances
                 WHERE account_id = ?1 AND disclaimer_hash = ?2
                 LIMIT 1",
                params![account_id, CURRENT_DISCLAIMER_HASH_HEX],
                |row| row.get(0),
            )
            .optional()
            .context("failed to query disclaimer acceptance")?;

        tx.commit().context("failed to commit transaction")?;

        Ok(DisclaimerState {
            disclaimer_text_md: CURRENT_DISCLAIMER_TEXT_MD.to_string(),
            disclaimer_hash_hex: CURRENT_DISCLAIMER_HASH_HEX.to_string(),
            accepted: accepted.is_some(),
        })
    }

    pub fn accept_current_disclaimer(
        &mut self,
        address: &str,
        disclaimer_hash_hex: &str,
    ) -> Result<()> {
        if disclaimer_hash_hex != CURRENT_DISCLAIMER_HASH_HEX {
            anyhow::bail!("Disclaimer hash mismatch. Please refresh and try again.");
        }

        let tx = self
            .conn
            .transaction()
            .context("failed to start transaction")?;
        let account_id = Self::get_or_create_account(&tx, address)?;

        tx.execute(
            "INSERT OR IGNORE INTO disclaimer_acceptances (account_id, disclaimer_hash)
             VALUES (?1, ?2)",
            params![account_id, disclaimer_hash_hex],
        )
        .context("failed to insert disclaimer acceptance")?;

        tx.commit().context("failed to commit transaction")?;
        Ok(())
    }

    pub fn get_bootnode_config(&self) -> Result<BootnodeConfig> {
        self.conn
            .query_row("SELECT enabled, url FROM bootnode_config", [], |row| {
                Ok(BootnodeConfig {
                    enabled: row.get::<_, i64>(0)? != 0,
                    url: row.get(1)?,
                })
            })
            .context("failed to query bootnode config")
    }

    pub fn set_bootnode_config(&mut self, enabled: bool, url: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE bootnode_config SET enabled = ?1, url = ?2",
                params![i64::from(enabled), url],
            )
            .context("failed to update bootnode config")?;
        Ok(())
    }

    /// Internal helper to handle the "Get or Create" logic for accounts
    fn get_or_create_account(tx: &rusqlite::Transaction, address: &str) -> Result<i64> {
        tx.execute(
            "INSERT OR IGNORE INTO accounts (address) VALUES (?1)",
            params![address],
        )
        .context("failed to insert account")?;

        let id: i64 = tx
            .query_row(
                "SELECT id FROM accounts WHERE address = ?1",
                params![address],
                |row| row.get(0),
            )
            .context("failed to fetch account id")?;

        Ok(id)
    }

    fn get_or_create_contract_id(tx: &rusqlite::Transaction, address: &str) -> Result<i64> {
        let id: i64 = tx
            .query_row(
                "INSERT INTO contracts (address)
                 VALUES (?1)
                 ON CONFLICT(address) DO UPDATE SET address = excluded.address
                 RETURNING contract_id",
                params![address],
                |row| row.get(0),
            )
            .context("failed to get or create contract id")?;

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

    /// List notes derived for `address` (newest first).
    pub fn list_user_notes(&self, address: &str, limit: u32) -> Result<Vec<UserNoteSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                n.id,
                n.amount,
                c.leaf_index,
                r.ledger,
                CASE WHEN n.nullifier_id IS NULL THEN 0 ELSE 1 END AS spent
             FROM user_notes n
             JOIN accounts a ON a.id = n.account_id
             JOIN pool_commitments c ON c.id = n.commitment_id
             JOIN raw_contract_events r ON r.id = c.event_id
             WHERE a.address = ?1
             ORDER BY r.ledger DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![address, limit], |row| {
            let id: Field = row.get(0)?;
            let amount: NoteAmount = row.get(1)?;
            let leaf_index_i64: i64 = row.get(2)?;
            let leaf_index = col_u32(leaf_index_i64, 2)?;
            let created_at_ledger_i64: i64 = row.get(3)?;
            let created_at_ledger = col_u32(created_at_ledger_i64, 3)?;
            let spent_i64: i64 = row.get(4)?;

            Ok(UserNoteSummary {
                id,
                amount,
                leaf_index,
                created_at_ledger,
                spent: spent_i64 != 0,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// All unspent notes for `address` in `pool_contract_id` (newest first).
    pub fn list_unspent_user_notes(
        &self,
        pool_contract_id: &str,
        address: &str,
    ) -> Result<Vec<UserNoteSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT
                n.id,
                n.amount,
                c.leaf_index,
                r.ledger
             FROM user_notes n
             JOIN accounts a ON a.id = n.account_id
             JOIN pool_commitments c ON c.id = n.commitment_id
             JOIN raw_contract_events r ON r.id = c.event_id
             JOIN contracts pool ON pool.contract_id = r.contract_id
             WHERE a.address = ?1 AND pool.address = ?2 AND n.nullifier_id IS NULL
             ORDER BY r.ledger DESC",
        )?;

        let rows = stmt.query_map(params![address, pool_contract_id], |row| {
            let id: Field = row.get(0)?;
            let amount: NoteAmount = row.get(1)?;
            let leaf_index_i64: i64 = row.get(2)?;
            let leaf_index = col_u32(leaf_index_i64, 2)?;
            let created_at_ledger_i64: i64 = row.get(3)?;
            let created_at_ledger = col_u32(created_at_ledger_i64, 3)?;

            Ok(UserNoteSummary {
                id,
                amount,
                leaf_index,
                created_at_ledger,
                spent: false,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Returns recent pool activity grouped by ledger (newest first).
    pub fn get_recent_pool_activity(&self, limit_ledgers: u32) -> Result<Vec<PoolLedgerActivity>> {
        let mut stmt = self.conn.prepare(
            "SELECT ledger, SUM(commitments) AS commitments, SUM(nullifiers) AS nullifiers
             FROM (
                SELECT r.ledger AS ledger, COUNT(*) AS commitments, 0 AS nullifiers
                FROM pool_commitments c
                JOIN raw_contract_events r ON r.id = c.event_id
                GROUP BY r.ledger
                UNION ALL
                SELECT r.ledger AS ledger, 0 AS commitments, COUNT(*) AS nullifiers
                FROM pool_nullifiers n
                JOIN raw_contract_events r ON r.id = n.event_id
                GROUP BY r.ledger
             )
             GROUP BY ledger
             ORDER BY ledger DESC
             LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit_ledgers], |row| {
            let ledger_i64: i64 = row.get(0)?;
            let ledger = col_u32(ledger_i64, 0)?;
            let commitments_i64: i64 = row.get(1)?;
            let commitments = col_u32(commitments_i64, 1)?;
            let nullifiers_i64: i64 = row.get(2)?;
            let nullifiers = col_u32(nullifiers_i64, 2)?;
            Ok(PoolLedgerActivity {
                ledger,
                commitments,
                nullifiers,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Fetch all pool commitments ordered by `leaf_index` (0..N-1) with no
    /// gaps.
    ///
    /// Returns the commitment list as [`Field`] values (each stored as 32-byte
    /// LE blob).
    ///
    /// Errors if there are gaps/out-of-order indices, because Merkle
    /// reconstruction would be ambiguous/incorrect.
    pub fn get_pool_commitment_leaves_ordered(&self, pool_contract_id: &str) -> Result<Vec<Field>> {
        let mut stmt = self.conn.prepare(
            "SELECT pc.leaf_index, pc.commitment
             FROM pool_commitments pc
             JOIN raw_contract_events r ON r.id = pc.event_id
             JOIN contracts c ON c.contract_id = r.contract_id
             WHERE c.address = ?1
             ORDER BY pc.leaf_index ASC",
        )?;

        let rows = stmt.query_map(params![pool_contract_id], |row| {
            let idx: i64 = row.get(0)?;
            let idx = col_u32(idx, 0)?;
            let commitment: Field = row.get(1)?;
            Ok((idx, commitment))
        })?;

        let mut leaves: Vec<Field> = Vec::new();
        let mut expected_index: u32 = 0;

        for row in rows {
            let (idx, leaf) = row?;
            if idx != expected_index {
                anyhow::bail!(
                    "pool_commitments gap/out-of-order: expected index {}, got {}",
                    expected_index,
                    idx
                );
            }
            leaves.push(leaf);
            expected_index = expected_index
                .checked_add(1)
                .context("pool_commitments index overflow")?;
        }

        Ok(leaves)
    }

    /// Lookup an unspent user note by pool commitment.
    ///
    /// Returns `(amount, blinding, leaf_index)` when found and unspent.
    pub fn get_unspent_user_note_by_commitment(
        &self,
        pool_contract_id: &str,
        account_address: &str,
        commitment: &Field,
    ) -> Result<Option<(NoteAmount, Field, u32)>> {
        let mut stmt = self.conn.prepare(
            "SELECT n.amount, n.blinding, pc.leaf_index
             FROM user_notes n
             JOIN accounts a ON a.id = n.account_id
             JOIN pool_commitments pc ON pc.id = n.commitment_id
             JOIN raw_contract_events r ON r.id = pc.event_id
             JOIN contracts c ON c.contract_id = r.contract_id
             WHERE a.address = ?2
               AND c.address = ?1
               AND pc.commitment = ?3
               AND n.nullifier_id IS NULL
             LIMIT 1",
        )?;

        let row = stmt
            .query_row(
                params![pool_contract_id, account_address, commitment],
                |row| {
                    let amount: NoteAmount = row.get(0)?;
                    let blinding: Field = row.get(1)?;
                    let leaf_index_i64: i64 = row.get(2)?;
                    let leaf_index = col_u32(leaf_index_i64, 2)?;
                    Ok((amount, blinding, leaf_index))
                },
            )
            .optional()
            .context("Failed to query unspent user note by commitment")?;

        Ok(row)
    }

    /// Batch upsert for spent nullifiers
    pub fn save_nullifier_events_batch(&mut self, events: &Vec<NewNullifierEvent>) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO pool_nullifiers (nullifier, event_id)
                    VALUES (?1, ?2)
                    ON CONFLICT(nullifier) DO NOTHING",
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
                    ON CONFLICT(commitment) DO NOTHING",
            )?;

            for event in events {
                stmt.execute(params![
                    event.commitment,
                    event.index,
                    event.encrypted_output,
                    event.id
                ])?;
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
                    ON CONFLICT(event_id) DO NOTHING",
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
                    ON CONFLICT(leaf_index) DO NOTHING",
            )?;

            for event in events {
                stmt.execute(params![event.index, event.leaf, event.root, event.id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Checks whether ASP membership data is usable for proving at the current
    /// network tip.
    ///
    /// Returns:
    /// - `AspMembershipSync::UserIndex(user_leaf_index)` if:
    ///   1) raw event ingestion is caught up to `current_ledger`,
    ///   2) `current_root` equals the last stored root in
    ///      `asp_membership_leaves`,
    ///   3) and `user_leaf` is present in `asp_membership_leaves`.
    /// - `AspMembershipSync::RegisterAtASP` if the DB is caught up but either:
    ///   1) no membership leaves have been observed yet, or
    ///   2) the user leaf is not present.
    /// - `AspMembershipSync::SyncRequired(Some(gap))` if:
    ///   1) the indexer is behind the chain tip, or
    ///   2) raw events are caught up but ASP membership leaf processing is
    ///      behind (root mismatch where the last stored leaf is from an earlier
    ///      ledger).
    /// - `Err(_)` if local metadata is ahead of the chain tip or if the root is
    ///   inconsistent at the same ledger (mismatched networks/corruption).
    pub fn check_asp_membership_precondition(
        &self,
        asp_membership_contract_id: &str,
        user_leaf: &Field,
        current_root: &Field,
        current_ledger: u32,
    ) -> Result<AspMembershipSync> {
        // The indexer sync metadata is authoritative for "how far we've indexed", even
        // if there were no ASP events in recent ledgers.
        let sync_meta = self
            .get_sync_metadata()?
            .into_iter()
            .find(|meta| meta.contract_id == asp_membership_contract_id);
        let Some(sync_meta) = sync_meta else {
            return Ok(AspMembershipSync::SyncRequired(Some(current_ledger)));
        };

        if current_ledger > sync_meta.last_fully_indexed_ledger {
            let gap = current_ledger.saturating_sub(sync_meta.last_fully_indexed_ledger);
            return Ok(AspMembershipSync::SyncRequired(Some(gap)));
        }

        if current_ledger < sync_meta.last_fully_indexed_ledger {
            anyhow::bail!(
                "indexer metadata is ahead of chain tip: local={}, chain={}",
                sync_meta.last_fully_indexed_ledger,
                current_ledger
            );
        }

        // Get the last stored root for the ASP membership tree and the ledger
        // that produced it. The ledger is derived by joining with the raw event
        // log so we can distinguish:
        // - "no new ASP events" (root matches, even if last leaf ledger < tip), vs
        // - "partial processing" (raw events ingested to tip but leaves table lags).
        let mut stmt = self.conn.prepare(
            "SELECT l.root, r.ledger
             FROM asp_membership_leaves l
             JOIN raw_contract_events r ON r.id = l.event_id
             JOIN contracts c ON c.contract_id = r.contract_id
             WHERE c.address = ?1
             ORDER BY l.leaf_index DESC
             LIMIT 1",
        )?;

        let last: Option<(Field, u32)> = stmt
            .query_row(params![asp_membership_contract_id], |row| {
                let root: Field = row.get(0)?;
                let ledger_i64: i64 = row.get(1)?;
                let ledger = col_u32(ledger_i64, 1)?;
                Ok((root, ledger))
            })
            .optional()
            .context("Failed to query asp_membership_leaves last root/ledger")?;

        let Some((last_root, last_leaf_ledger)) = last else {
            return Ok(AspMembershipSync::RegisterAtASP);
        };

        // current_ledger == last_fully_indexed_ledger: require root match and leaf
        // existence.
        if *current_root != last_root {
            // If the root at the chain tip doesn't match the last stored root
            // but our last stored leaf is from an earlier ledger, we may have
            // ingested raw events without yet processing them into
            // asp_membership_leaves.
            if last_leaf_ledger < current_ledger {
                let gap = current_ledger.saturating_sub(last_leaf_ledger);
                return Ok(AspMembershipSync::SyncRequired(Some(gap)));
            }
            anyhow::bail!("asp membership root mismatch at ledger {}", current_ledger);
        }

        let mut stmt = self.conn.prepare(
            "SELECT l.leaf_index
             FROM asp_membership_leaves l
             JOIN raw_contract_events r ON r.id = l.event_id
             JOIN contracts c ON c.contract_id = r.contract_id
             WHERE l.leaf = ?1 AND c.address = ?2
             LIMIT 1",
        )?;

        let user_leaf_index: Option<u32> = stmt
            .query_row(params![user_leaf, asp_membership_contract_id], |row| {
                row.get(0)
            })
            .optional()
            .context("Failed to query asp_membership_leaves user leaf existence")?;

        if let Some(user_leaf_index) = user_leaf_index {
            return Ok(AspMembershipSync::UserIndex(user_leaf_index));
        }

        Ok(AspMembershipSync::RegisterAtASP)
    }

    // TODO ideally we should return an iterator here
    /// Fetch all ASP membership leaves ordered by index (0..N-1), returning the
    /// leaf list plus the last stored root (root after the last insertion).
    ///
    /// Errors if there are gaps/out-of-order indices, because Merkle
    /// reconstruction would be ambiguous/incorrect.
    pub fn get_all_asp_membership_leaves_ordered(
        &self,
        asp_membership_contract_id: &str,
    ) -> Result<Vec<Field>> {
        let mut stmt = self.conn.prepare(
            "SELECT l.leaf_index, l.leaf
             FROM asp_membership_leaves l
             JOIN raw_contract_events r ON r.id = l.event_id
             JOIN contracts c ON c.contract_id = r.contract_id
             WHERE c.address = ?1
             ORDER BY l.leaf_index ASC",
        )?;

        let rows = stmt.query_map(params![asp_membership_contract_id], |row| {
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
            "SELECT r.id, r.ledger, c.address, r.topics, r.value
                FROM raw_contract_events r
                JOIN contracts c ON c.contract_id = r.contract_id
                LEFT JOIN pool_commitments pc ON r.id = pc.event_id
                LEFT JOIN public_keys p ON r.id = p.event_id
                LEFT JOIN asp_membership_leaves l ON r.id = l.event_id
                LEFT JOIN pool_nullifiers n ON r.id = n.event_id
                WHERE pc.event_id IS NULL
                AND p.event_id IS NULL
                AND n.event_id IS NULL
                AND l.event_id IS NULL
                ORDER BY r.ledger ASC, r.id ASC
                LIMIT ?1",
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
                k.note_public_key,
                k.membership_blinding
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
            let membership_blinding: Field = row.get(5)?;

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
                membership_blinding,
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
        const ACCOUNT_CHUNK: u32 = 4;

        let accounts = self.get_accounts_with_latest_keypairs()?;
        if accounts.is_empty() || total_limit == 0 {
            return Ok(false);
        }

        let pool_ids: Vec<i64> = self
            .conn
            .prepare(
                "SELECT DISTINCT r.contract_id
                 FROM pool_commitments c
                 JOIN raw_contract_events r ON r.id = c.event_id
                 ORDER BY r.contract_id",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<core::result::Result<Vec<i64>, _>>()?;

        if pool_ids.is_empty() {
            return Ok(false);
        }

        let pool_count_u32 =
            u32::try_from(pool_ids.len()).map_err(|_| anyhow::anyhow!("pool count exceeds u32"))?;
        let base_quota = if pool_count_u32 == 0 {
            0
        } else if total_limit >= pool_count_u32 {
            total_limit
                .checked_div(pool_count_u32)
                .expect("pool count is not zero")
        } else {
            log::warn!(
                "pool count {pool_count_u32} exceeds total limit {total_limit} of commitments to scan"
            );
            1
        };

        let mut quotas = vec![base_quota; pool_ids.len()];
        let assigned = base_quota.saturating_mul(pool_count_u32);
        let mut remainder = total_limit.saturating_sub(assigned);
        let mut next_pool = 0usize;
        while remainder > 0 {
            quotas[next_pool] = quotas[next_pool].saturating_add(1);
            remainder = remainder.saturating_sub(1);
            next_pool = (next_pool
                .checked_add(1)
                .expect("next_pool shouldn't overflow"))
            .checked_rem(pool_ids.len())
            .expect("pool ids is not zero");
        }

        let mut did_any_progress = false;

        for (pool_idx, pool_contract_id) in pool_ids.iter().enumerate() {
            let mut pool_quota = quotas[pool_idx];
            if pool_quota == 0 {
                continue;
            }

            let tx = self.conn.transaction()?;

            for account in &accounts {
                tx.execute(
                    "INSERT OR IGNORE INTO account_commitment_scan (pool_contract_id, account_id, last_commitment_id)
                     VALUES (?1, ?2, 0)",
                    params![pool_contract_id, account.account_id],
                )?;
            }

            let mut did_progress_in_pool = false;

            while pool_quota > 0 {
                let mut progressed_this_cycle = false;

                for account in &accounts {
                    if pool_quota == 0 {
                        break;
                    }

                    let last_commitment_id: i64 = tx.query_row(
                        "SELECT last_commitment_id
                         FROM account_commitment_scan
                         WHERE pool_contract_id = ?1 AND account_id = ?2",
                        params![pool_contract_id, account.account_id],
                        |row| row.get(0),
                    )?;

                    let quota = pool_quota.min(ACCOUNT_CHUNK);
                    let commitments: Vec<PoolCommitmentRow> = {
                        let mut stmt = tx.prepare(
                            "SELECT c.id, c.commitment, c.leaf_index, c.encrypted_output
                             FROM pool_commitments c
                             JOIN raw_contract_events r ON r.id = c.event_id
                             WHERE r.contract_id = ?1 AND c.id > ?2
                             ORDER BY c.id ASC
                             LIMIT ?3",
                        )?;

                        let rows = stmt.query_map(
                            params![pool_contract_id, last_commitment_id, quota],
                            |row| {
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
                            },
                        )?;

                        let mut out = Vec::new();
                        for r in rows {
                            out.push(r?);
                        }
                        out
                    };

                    if commitments.is_empty() {
                        continue;
                    }

                    progressed_this_cycle = true;
                    did_progress_in_pool = true;

                    let mut max_scanned_id = last_commitment_id;
                    let scanned_count = u32::try_from(commitments.len())
                        .map_err(|_| anyhow::anyhow!("commitments batch length exceeds u32"))?;

                    for row in commitments {
                        if row.commitment_id > max_scanned_id {
                            max_scanned_id = row.commitment_id;
                        }

                        let Some(derived) = derive(account, &row)? else {
                            continue;
                        };

                        let nullifier_id: Option<i64> = tx
                            .query_row(
                                "SELECT n.id
                                 FROM pool_nullifiers n
                                 JOIN raw_contract_events r ON r.id = n.event_id
                                 WHERE r.contract_id = ?1 AND n.nullifier = ?2
                                 LIMIT 1",
                                params![pool_contract_id, derived.expected_nullifier],
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
                                derived.amount.to_string()
                            ],
                        )?;
                    }

                    tx.execute(
                        "UPDATE account_commitment_scan
                         SET last_commitment_id = ?1
                         WHERE pool_contract_id = ?2 AND account_id = ?3",
                        params![max_scanned_id, pool_contract_id, account.account_id],
                    )?;

                    pool_quota = pool_quota.saturating_sub(scanned_count);
                }

                if !progressed_this_cycle {
                    break;
                }
            }

            tx.commit()?;
            did_any_progress |= did_progress_in_pool;
        }

        Ok(did_any_progress)
    }

    pub fn reconcile_nullifiers(&mut self, limit: u32) -> Result<bool> {
        if limit == 0 {
            return Ok(false);
        }

        let pool_ids: Vec<i64> = self
            .conn
            .prepare(
                "SELECT DISTINCT r.contract_id
                 FROM pool_nullifiers n
                 JOIN raw_contract_events r ON r.id = n.event_id
                 ORDER BY r.contract_id",
            )?
            .query_map([], |row| row.get(0))?
            .collect::<core::result::Result<Vec<i64>, _>>()?;

        if pool_ids.is_empty() {
            return Ok(false);
        }

        let mut did_any = false;

        for pool_contract_id in pool_ids {
            let tx = self.conn.transaction()?;

            tx.execute(
                "INSERT OR IGNORE INTO nullifier_scan_state (pool_contract_id, last_nullifier_id)
                 VALUES (?1, 0)",
                params![pool_contract_id],
            )?;

            let last_nullifier_id: i64 = tx.query_row(
                "SELECT last_nullifier_id FROM nullifier_scan_state WHERE pool_contract_id = ?1",
                params![pool_contract_id],
                |row| row.get(0),
            )?;

            let nullifiers: Vec<(i64, Field)> = {
                let mut stmt = tx.prepare(
                    "SELECT n.id, n.nullifier
                     FROM pool_nullifiers n
                     JOIN raw_contract_events r ON r.id = n.event_id
                     WHERE r.contract_id = ?1 AND n.id > ?2
                     ORDER BY n.id ASC
                     LIMIT ?3",
                )?;

                let rows =
                    stmt.query_map(params![pool_contract_id, last_nullifier_id, limit], |row| {
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

            for (nullifier_id, nullifier) in nullifiers {
                did_any = true;
                if nullifier_id > max_id {
                    max_id = nullifier_id;
                }

                tx.execute(
                    "UPDATE user_notes
                     SET nullifier_id = ?1
                     WHERE nullifier_id IS NULL
                       AND expected_nullifier = ?2
                       AND EXISTS (
                           SELECT 1
                           FROM pool_commitments c
                           JOIN raw_contract_events r ON r.id = c.event_id
                           WHERE c.id = user_notes.commitment_id
                             AND r.contract_id = ?3
                       )",
                    params![nullifier_id, nullifier, pool_contract_id],
                )?;
            }

            if max_id > last_nullifier_id {
                tx.execute(
                    "UPDATE nullifier_scan_state
                     SET last_nullifier_id = ?1
                     WHERE pool_contract_id = ?2",
                    params![max_id, pool_contract_id],
                )?;
            }

            tx.commit()?;
        }

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
        ContractEvent, ContractsEventData, EncryptionPublicKey, KeyDerivationSignature, NoteAmount,
        NotePublicKey, PublicKeyEvent,
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
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let event_id = "pk_event_1";
        storage.save_events_batch(&ContractsEventData {
            cursor: "cursor".to_string(),
            latest_ledger: 42,
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
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        // Create an account with keypairs.
        let signature = KeyDerivationSignature(vec![1u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(signature.clone())?;
        let membership_blinding = encryption::derive_membership_blinding(&signature, "testnet")?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;

        let account_id: i64 = storage.conn.query_row(
            "SELECT id FROM accounts WHERE address = ?1",
            params!["GTESTACCOUNT"],
            |row| row.get(0),
        )?;

        // Build a commitment + encrypted output addressed to the account.
        let amount = NoteAmount::from(5);
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = 7;
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
            encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;

        // Insert the raw event + the parsed pool commitment row.
        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-commit")],
            cursor: "cur".to_string(),
            latest_ledger: 1,
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

        let note_count: i64 =
            storage
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
        let signature = crypto::compute_signature(
            &note_keypair.private.0,
            &commitment.to_le_bytes(),
            &path_indices_le,
        )?;
        let nullifier_le =
            crypto::compute_nullifier(&commitment.to_le_bytes(), &path_indices_le, &signature)?;
        let nullifier_le: [u8; 32] = nullifier_le.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("nullifier: expected 32 bytes, got {}", v.len())
        })?;
        let nullifier = Field::try_from_le_bytes(nullifier_le)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-null")],
            cursor: "cur2".to_string(),
            latest_ledger: 1,
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

    #[test]
    fn sync_metadata_tracks_progress_and_caught_up_tip() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        storage.save_events_batch(&ContractsEventData {
            cursor: "c1".to_string(),
            latest_ledger: 10,
            events: vec![dummy_event("evt-1")],
        })?;
        storage.save_sync_progress(
            &[types::SyncMetadata {
                contract_id: "CPOOL".to_string(),
                cursor: "c1".to_string(),
                last_indexed_ledger: 10,
                last_fully_indexed_ledger: 0,
            }],
            false,
        )?;

        let meta = storage
            .get_sync_metadata()?
            .into_iter()
            .find(|meta| meta.contract_id == "CPOOL")
            .expect("expected sync metadata");
        assert_eq!(meta.cursor, "c1");
        assert_eq!(meta.last_indexed_ledger, 10);
        assert_eq!(meta.last_fully_indexed_ledger, 0);

        storage.save_events_batch(&ContractsEventData {
            cursor: "c2".to_string(),
            latest_ledger: 123,
            events: vec![],
        })?;
        storage.save_sync_progress(
            &[types::SyncMetadata {
                contract_id: "CPOOL".to_string(),
                cursor: "c2".to_string(),
                last_indexed_ledger: 123,
                last_fully_indexed_ledger: 0,
            }],
            true,
        )?;

        let meta = storage
            .get_sync_metadata()?
            .into_iter()
            .find(|meta| meta.contract_id == "CPOOL")
            .expect("expected sync metadata");
        assert_eq!(meta.cursor, "c2");
        assert_eq!(meta.last_indexed_ledger, 123);
        assert_eq!(meta.last_fully_indexed_ledger, 123);

        storage.clear_indexing_cursors()?;
        let meta = storage
            .get_sync_metadata()?
            .into_iter()
            .find(|meta| meta.contract_id == "CPOOL")
            .expect("expected sync metadata");
        assert!(meta.cursor.is_empty());
        assert_eq!(meta.last_indexed_ledger, 123);
        assert_eq!(meta.last_fully_indexed_ledger, 123);

        Ok(())
    }

    #[test]
    fn get_user_keys_returns_latest_keypair() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let signature_1 = KeyDerivationSignature(vec![1u8; 64]);
        let signature_2 = KeyDerivationSignature(vec![3u8; 64]);
        let (note_keypair_1, enc_keypair_1) =
            encryption::derive_encryption_and_note_keypairs(signature_1.clone())?;
        let (note_keypair_2, enc_keypair_2) =
            encryption::derive_encryption_and_note_keypairs(signature_2.clone())?;
        let membership_blinding_1 =
            encryption::derive_membership_blinding(&signature_1, "testnet")?;
        let membership_blinding_2 =
            encryption::derive_membership_blinding(&signature_2, "testnet")?;

        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair_1,
            &enc_keypair_1,
            &membership_blinding_1,
        )?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair_2,
            &enc_keypair_2,
            &membership_blinding_2,
        )?;

        let keys = storage
            .get_user_keys("GTESTACCOUNT")?
            .expect("expected keypairs to exist");
        assert_eq!(keys.note_keypair.public.0, note_keypair_2.public.0);
        assert_eq!(keys.encryption_keypair.public.0, enc_keypair_2.public.0);
        assert_eq!(
            keys.membership_blinding.to_le_bytes(),
            membership_blinding_2.to_le_bytes()
        );

        Ok(())
    }

    #[test]
    fn save_keypairs_does_not_duplicate_accounts() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let signature = KeyDerivationSignature(vec![1u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(signature.clone())?;
        let membership_blinding = encryption::derive_membership_blinding(&signature, "testnet")?;

        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;

        let count: i64 = storage.conn.query_row(
            "SELECT COUNT(*) FROM accounts WHERE address = ?1",
            params!["GTESTACCOUNT"],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);

        Ok(())
    }

    #[test]
    fn asp_membership_precondition_partial_processing_returns_sync_required() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let mut root_old_bytes = [0u8; 32];
        root_old_bytes[0] = 1;
        let root_old = Field::try_from_le_bytes(root_old_bytes)?;

        let mut root_new_bytes = [0u8; 32];
        root_new_bytes[0] = 2;
        let root_new = Field::try_from_le_bytes(root_new_bytes)?;

        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[0] = 3;
        let leaf = Field::try_from_le_bytes(leaf_bytes)?;

        let last_leaf_ledger = 10u32;
        let current_ledger = 12u32;

        // Ingest raw events (including a newer ASP event)...
        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-raw".to_string(),
            latest_ledger: 11,
            events: vec![
                ContractEvent {
                    id: "asp-leaf-10".to_string(),
                    ledger: last_leaf_ledger,
                    contract_id: "CASP".to_string(),
                    topics: vec!["leaf_added".to_string()],
                    value: "dummy".to_string(),
                },
                ContractEvent {
                    id: "asp-leaf-11-unprocessed".to_string(),
                    ledger: 11,
                    contract_id: "CASP".to_string(),
                    topics: vec!["leaf_added".to_string()],
                    value: "dummy".to_string(),
                },
            ],
        })?;

        // ...but only process the older one into asp_membership_leaves.
        storage.save_leaf_added_events_batch(&vec![LeafAddedEvent {
            id: "asp-leaf-10".to_string(),
            leaf,
            index: 0,
            root: root_old,
        }])?;

        // Mark the indexer as fully caught up to the chain tip (even though
        // event processing is behind).
        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-tip".to_string(),
            latest_ledger: current_ledger,
            events: vec![],
        })?;
        storage.save_sync_progress(
            &[types::SyncMetadata {
                contract_id: "CASP".to_string(),
                cursor: "cur-tip".to_string(),
                last_indexed_ledger: current_ledger,
                last_fully_indexed_ledger: 0,
            }],
            true,
        )?;

        // Root matches the last stored root: this should NOT require syncing
        // even if the last ASP leaf was emitted earlier than the current tip.
        let status =
            storage.check_asp_membership_precondition("CASP", &leaf, &root_new, current_ledger)?;
        assert!(matches!(
            status,
            AspMembershipSync::SyncRequired(Some(gap)) if gap == current_ledger - last_leaf_ledger
        ));
        Ok(())
    }

    #[test]
    fn asp_membership_precondition_root_mismatch_at_same_ledger_errors() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let mut root_old_bytes = [0u8; 32];
        root_old_bytes[0] = 1;
        let root_old = Field::try_from_le_bytes(root_old_bytes)?;

        let mut root_new_bytes = [0u8; 32];
        root_new_bytes[0] = 2;
        let root_new = Field::try_from_le_bytes(root_new_bytes)?;

        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[0] = 3;
        let leaf = Field::try_from_le_bytes(leaf_bytes)?;

        let current_ledger = 10u32;

        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-raw".to_string(),
            latest_ledger: current_ledger,
            events: vec![ContractEvent {
                id: "asp-leaf-10".to_string(),
                ledger: current_ledger,
                contract_id: "CASP".to_string(),
                topics: vec!["leaf_added".to_string()],
                value: "dummy".to_string(),
            }],
        })?;

        storage.save_leaf_added_events_batch(&vec![LeafAddedEvent {
            id: "asp-leaf-10".to_string(),
            leaf,
            index: 0,
            root: root_old,
        }])?;

        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-tip".to_string(),
            latest_ledger: current_ledger,
            events: vec![],
        })?;
        storage.save_sync_progress(
            &[types::SyncMetadata {
                contract_id: "CASP".to_string(),
                cursor: "cur-tip".to_string(),
                last_indexed_ledger: current_ledger,
                last_fully_indexed_ledger: 0,
            }],
            true,
        )?;

        let err = storage
            .check_asp_membership_precondition("CASP", &leaf, &root_new, current_ledger)
            .expect_err("root mismatch at same ledger should be an error");
        assert!(err.to_string().contains("asp membership root mismatch"));
        Ok(())
    }

    #[test]
    fn asp_membership_precondition_allows_tip_without_recent_asp_events() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let mut root_bytes = [0u8; 32];
        root_bytes[0] = 1;
        let root = Field::try_from_le_bytes(root_bytes)?;

        let mut leaf_bytes = [0u8; 32];
        leaf_bytes[0] = 3;
        let leaf = Field::try_from_le_bytes(leaf_bytes)?;

        let last_leaf_ledger = 10u32;
        let current_ledger = 12u32;

        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-raw".to_string(),
            latest_ledger: last_leaf_ledger,
            events: vec![ContractEvent {
                id: "asp-leaf-10".to_string(),
                ledger: last_leaf_ledger,
                contract_id: "CASP".to_string(),
                topics: vec!["leaf_added".to_string()],
                value: "dummy".to_string(),
            }],
        })?;

        storage.save_leaf_added_events_batch(&vec![LeafAddedEvent {
            id: "asp-leaf-10".to_string(),
            leaf,
            index: 0,
            root,
        }])?;

        storage.save_events_batch(&ContractsEventData {
            cursor: "cur-tip".to_string(),
            latest_ledger: current_ledger,
            events: vec![],
        })?;
        storage.save_sync_progress(
            &[types::SyncMetadata {
                contract_id: "CASP".to_string(),
                cursor: "cur-tip".to_string(),
                last_indexed_ledger: current_ledger,
                last_fully_indexed_ledger: 0,
            }],
            true,
        )?;

        let status =
            storage.check_asp_membership_precondition("CASP", &leaf, &root, current_ledger)?;
        assert!(!matches!(status, AspMembershipSync::SyncRequired(_)));
        Ok(())
    }

    #[test]
    fn get_unspent_user_note_by_commitment_finds_unspent_note() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let sig = KeyDerivationSignature(vec![1u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(sig.clone())?;
        let membership_blinding = encryption::derive_membership_blinding(&sig, "testnet")?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;

        let amount = NoteAmount::from(5);
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = 7;
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
            encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-commit")],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: "evt-commit".to_string(),
            commitment,
            index: 3,
            encrypted_output: encrypted_output.clone(),
        }])?;

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

        let result =
            storage.get_unspent_user_note_by_commitment("CPOOL", "GTESTACCOUNT", &commitment)?;
        assert!(result.is_some());
        let (got_amount, got_blinding, got_leaf_index) = result.expect("just checked is_some");
        assert_eq!(got_amount, amount);
        assert_eq!(got_blinding, blinding);
        assert_eq!(got_leaf_index, 3);

        Ok(())
    }

    #[test]
    fn get_unspent_user_note_by_commitment_rejects_spent_note() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let sig = KeyDerivationSignature(vec![1u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(sig.clone())?;
        let membership_blinding = encryption::derive_membership_blinding(&sig, "testnet")?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;

        let amount = NoteAmount::from(5);
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = 7;
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
            encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-commit")],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: "evt-commit".to_string(),
            commitment,
            index: 3,
            encrypted_output: encrypted_output.clone(),
        }])?;

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
        storage.scan_commitments_for_user_notes(100, &mut derive)?;

        // Spend the note via nullifier.
        let leaf_index: u32 = 3;
        let mut path_indices_le = [0u8; 32];
        path_indices_le[..8].copy_from_slice(&(u64::from(leaf_index)).to_le_bytes());
        let signature = crypto::compute_signature(
            &note_keypair.private.0,
            &commitment.to_le_bytes(),
            &path_indices_le,
        )?;
        let nullifier_le =
            crypto::compute_nullifier(&commitment.to_le_bytes(), &path_indices_le, &signature)?;
        let nullifier_le: [u8; 32] = nullifier_le.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("nullifier: expected 32 bytes, got {}", v.len())
        })?;
        let nullifier = Field::try_from_le_bytes(nullifier_le)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-null")],
            cursor: "cur2".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_nullifier_events_batch(&vec![NewNullifierEvent {
            id: "evt-null".to_string(),
            nullifier,
        }])?;
        storage.reconcile_nullifiers(100)?;

        let result =
            storage.get_unspent_user_note_by_commitment("CPOOL", "GTESTACCOUNT", &commitment)?;
        assert!(result.is_none(), "spent note should not be returned");

        Ok(())
    }

    #[test]
    fn get_unspent_user_note_by_commitment_rejects_wrong_commitment() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let sig = KeyDerivationSignature(vec![1u8; 64]);
        let (note_keypair, enc_keypair) =
            encryption::derive_encryption_and_note_keypairs(sig.clone())?;
        let membership_blinding = encryption::derive_membership_blinding(&sig, "testnet")?;
        storage.save_encryption_and_note_keypairs(
            "GTESTACCOUNT",
            &note_keypair,
            &enc_keypair,
            &membership_blinding,
        )?;

        let amount = NoteAmount::from(5);
        let mut blinding_le = [0u8; 32];
        blinding_le[0] = 7;
        let blinding = Field::try_from_le_bytes(blinding_le)?;

        let encrypted_output =
            encryption::encrypt_output_note(&enc_keypair.public, amount, &blinding)?;

        let mut commitment_le = [0u8; 32];
        commitment_le[0] = 1;
        let commitment = Field::try_from_le_bytes(commitment_le)?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-commit")],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_commitment_events_batch(&vec![NewCommitmentEvent {
            id: "evt-commit".to_string(),
            commitment,
            index: 0,
            encrypted_output: encrypted_output.clone(),
        }])?;

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
        storage.scan_commitments_for_user_notes(100, &mut derive)?;

        let wrong_commitment = Field::try_from_le_bytes([
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])?;
        let result = storage.get_unspent_user_note_by_commitment(
            "CPOOL",
            "GTESTACCOUNT",
            &wrong_commitment,
        )?;
        assert!(result.is_none(), "wrong commitment should not match");

        Ok(())
    }

    #[test]
    fn get_pool_commitment_leaves_ordered_returns_ordered_leaves() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let leaf0 = Field::try_from_le_bytes([0u8; 32])?;
        let leaf1 = Field::try_from_le_bytes([1u8; 32])?;
        let leaf2 = Field::try_from_le_bytes([2u8; 32])?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![
                dummy_event("evt-0"),
                dummy_event("evt-1"),
                dummy_event("evt-2"),
            ],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_commitment_events_batch(&vec![
            NewCommitmentEvent {
                id: "evt-0".to_string(),
                commitment: leaf0,
                index: 0,
                encrypted_output: vec![],
            },
            NewCommitmentEvent {
                id: "evt-1".to_string(),
                commitment: leaf1,
                index: 1,
                encrypted_output: vec![],
            },
            NewCommitmentEvent {
                id: "evt-2".to_string(),
                commitment: leaf2,
                index: 2,
                encrypted_output: vec![],
            },
        ])?;

        let leaves = storage.get_pool_commitment_leaves_ordered("CPOOL")?;
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0], leaf0);
        assert_eq!(leaves[1], leaf1);
        assert_eq!(leaves[2], leaf2);

        Ok(())
    }

    #[test]
    fn get_pool_commitment_leaves_ordered_detects_gaps() -> Result<()> {
        let mut storage = Storage::connect_with_connection(Connection::open_in_memory()?)?;

        let leaf0 = Field::try_from_le_bytes([0u8; 32])?;
        let leaf2 = Field::try_from_le_bytes([2u8; 32])?;

        storage.save_events_batch(&ContractsEventData {
            events: vec![dummy_event("evt-0"), dummy_event("evt-2")],
            cursor: "cur".to_string(),
            latest_ledger: 1,
        })?;
        storage.save_commitment_events_batch(&vec![
            NewCommitmentEvent {
                id: "evt-0".to_string(),
                commitment: leaf0,
                index: 0,
                encrypted_output: vec![],
            },
            NewCommitmentEvent {
                id: "evt-2".to_string(),
                commitment: leaf2,
                index: 2,
                encrypted_output: vec![],
            },
        ])?;

        let err = storage
            .get_pool_commitment_leaves_ordered("CPOOL")
            .expect_err("gap should error");
        assert!(err.to_string().contains("gap/out-of-order"));

        Ok(())
    }
}
