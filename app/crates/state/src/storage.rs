use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, params, Error as SqlError};
use rusqlite_migration::{M, Migrations};

// shouldn't be changed for WASM OPFS otherwise the db will be lost
const DB_NAME: &str = "spp.sqlite";

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

    pub fn save_events_batch(&self, cursor: Option<String>, events: &[stellar::Event]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO events (id, ledger, type, contract_id, topic, value)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO NOTHING"
            )?;

            for event in events {
                if let Some(topic) = event.topic.first() {
                    stmt.execute(params![
                        event.id,
                        event.ledger,
                        event.event_type,
                        event.contract_id,
                        topic,
                        event.value
                    ])?;
                } else {
                    log::warn!("Event {} emitted by contract {} contains no topics", event.id, event.contract_id);
                }
            }

            if let Some(cursor) = cursor {
                tx.execute(
                    "INSERT OR REPLACE INTO indexing_metadata (id, last_cursor) VALUES (1, ?1)",
                    params![cursor],
                )?;
            }
        }
        tx.commit()?;

        Ok(())
    }

    pub fn get_synced_ledger_and_cursor(conn: &Connection) -> Result<(Option<u32>, Option<String>)> {
        let mut stmt = conn.prepare(
            "SELECT MAX(e.ledger), m.last_cursor
             FROM events e
             CROSS JOIN indexing_metadata m
             WHERE m.id = 1"
        )?;

        let status = stmt.query_row([], |row| {
            let ledger: Option<u32> = row.get(0)?;
            let cursor: Option<String> = row.get(1)?;
            Ok((ledger, cursor))
        })?;

        Ok(status)
    }

    // -----------------------------------------------------------------------
    // pool_leaves
    // -----------------------------------------------------------------------

    /// Inserts or replaces a pool leaf.
    pub fn put_pool_leaf(&self, leaf: &types::PoolLeaf) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO pool_leaves (leaf_index, commitment, ledger)
                     VALUES (?1, ?2, ?3)",
                params![
                    i64::from(leaf.index),
                    &leaf.commitment,
                    i64::from(leaf.ledger)
                ],
            )
            .context("put_pool_leaf")?;
        Ok(())
    }

    // /// Iterates over pool leaves in ascending index order.
    // /// Callback returns `false` to stop early.
    // pub fn iterate_pool_leaves(
    //     &self,
    //     mut callback: impl FnMut(PoolLeaf) -> bool,
    // ) -> Result<()> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT leaf_index, commitment, ledger
    //                  FROM pool_leaves ORDER BY leaf_index ASC",
    //         )
    //         .context("prepare iterate_pool_leaves")?;
    //     let mut rows = stmt.query([]).context("iterate_pool_leaves")?;
    //     while let Some(row) = rows.next().context("iterate_pool_leaves next")? {
    //         let leaf = PoolLeaf {
    //             index: col_u32(row.get::<_, i64>(0)?, 0)?,
    //             commitment: row.get(1)?,
    //             ledger: col_u32(row.get::<_, i64>(2)?, 2)?,
    //         };
    //         if !callback(leaf) {
    //             break;
    //         }
    //     }
    //     Ok(())
    // }

    /// Returns the total number of pool leaves.
    pub fn count_pool_leaves(&self) -> Result<u32> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pool_leaves", [], |row| row.get(0))
            .context("count_pool_leaves")?;
        u32::try_from(n).context("count overflow")
    }

    // /// Inserts or replaces a batch of pool leaves in a single transaction.
    // pub fn put_pool_leaves_batch(&self, leaves: &[PoolLeaf]) -> anyhow::Result<()> {
    //     if leaves.is_empty() {
    //         return Ok(());
    //     }
    //     let tx = self
    //         .conn
    //         .unchecked_transaction()
    //         .context("put_pool_leaves_batch begin")?;
    //     {
    //         let mut stmt = tx
    //             .prepare(
    //                 "INSERT OR REPLACE INTO pool_leaves (leaf_index, commitment, ledger)
    //                      VALUES (?1, ?2, ?3)",
    //             )
    //             .context("prepare put_pool_leaves_batch")?;
    //         for leaf in leaves {
    //             stmt.execute(params![
    //                 i64::from(leaf.index),
    //                 &leaf.commitment,
    //                 i64::from(leaf.ledger)
    //             ])
    //             .context("put_pool_leaves_batch execute")?;
    //         }
    //     }
    //     tx.commit().context("put_pool_leaves_batch commit")
    // }

    // /// Deletes all pool leaves.
    // pub fn clear_pool_leaves(&self) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM pool_leaves", [])
    //         .context("clear_pool_leaves")?;
    //     Ok(())
    // }

    // // -----------------------------------------------------------------------
    // // pool_nullifiers
    // // -----------------------------------------------------------------------

    // /// Inserts or replaces a nullifier record.
    // pub fn put_nullifier(&self, nullifier: &PoolNullifier) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO pool_nullifiers (nullifier, ledger) VALUES (?1, ?2)",
    //             params![&nullifier.nullifier, i64::from(nullifier.ledger)],
    //         )
    //         .context("put_nullifier")?;
    //     Ok(())
    // }

    // /// Returns the nullifier record for `nullifier`, or `None` if unspent.
    // pub fn get_nullifier(&self, nullifier: &str) -> anyhow::Result<Option<PoolNullifier>> {
    //     let result = self.conn.query_row(
    //         "SELECT nullifier, ledger FROM pool_nullifiers WHERE nullifier = ?1",
    //         params![nullifier],
    //         |row| {
    //             Ok(PoolNullifier {
    //                 nullifier: row.get(0)?,
    //                 ledger: col_u32(row.get::<_, i64>(1)?, 1)?,
    //             })
    //         },
    //     );
    //     match result {
    //         Ok(n) => Ok(Some(n)),
    //         Err(SqlError::QueryReturnedNoRows) => Ok(None),
    //         Err(e) => Err(e).context("get_nullifier"),
    //     }
    // }

    // /// Returns the total number of spent nullifiers.
    // pub fn count_nullifiers(&self) -> anyhow::Result<u32> {
    //     let n: i64 = self
    //         .conn
    //         .query_row("SELECT COUNT(*) FROM pool_nullifiers", [], |row| row.get(0))
    //         .context("count_nullifiers")?;
    //     u32::try_from(n).context("count overflow")
    // }

    // /// Deletes all nullifiers.
    // pub fn clear_nullifiers(&self) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM pool_nullifiers", [])
    //         .context("clear_nullifiers")?;
    //     Ok(())
    // }

    // // -----------------------------------------------------------------------
    // // pool_encrypted_outputs
    // // -----------------------------------------------------------------------

    // /// Inserts or replaces an encrypted output.
    // pub fn put_encrypted_output(&self, output: &PoolEncryptedOutput) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO pool_encrypted_outputs
    //                  (commitment, leaf_index, encrypted_output, ledger)
    //                  VALUES (?1, ?2, ?3, ?4)",
    //             params![
    //                 &output.commitment,
    //                 i64::from(output.leaf_index),
    //                 &output.encrypted_output,
    //                 i64::from(output.ledger),
    //             ],
    //         )
    //         .context("put_encrypted_output")?;
    //     Ok(())
    // }

    // /// Returns all encrypted outputs.
    // pub fn get_all_encrypted_outputs(&self) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT commitment, leaf_index, encrypted_output, ledger
    //                  FROM pool_encrypted_outputs",
    //         )
    //         .context("prepare get_all_encrypted_outputs")?;
    //     stmt.query_map([], map_encrypted_output)
    //         .context("get_all_encrypted_outputs")?
    //         .collect::<Result<Vec<_>, _>>()
    //         .context("get_all_encrypted_outputs collect")
    // }

    // /// Returns encrypted outputs with `ledger >= from_ledger`.
    // pub fn get_encrypted_outputs_from(
    //     &self,
    //     from_ledger: u32,
    // ) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT commitment, leaf_index, encrypted_output, ledger
    //                  FROM pool_encrypted_outputs WHERE ledger >= ?1",
    //         )
    //         .context("prepare get_encrypted_outputs_from")?;
    //     stmt.query_map(params![i64::from(from_ledger)], map_encrypted_output)
    //         .context("get_encrypted_outputs_from")?
    //         .collect::<Result<Vec<_>, _>>()
    //         .context("get_encrypted_outputs_from collect")
    // }

    // /// Deletes all encrypted outputs.
    // pub fn clear_encrypted_outputs(&self) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM pool_encrypted_outputs", [])
    //         .context("clear_encrypted_outputs")?;
    //     Ok(())
    // }

    // // -----------------------------------------------------------------------
    // // asp_membership_leaves
    // // -----------------------------------------------------------------------

    // /// Inserts or replaces an ASP membership leaf.
    // pub fn put_asp_membership_leaf(&self, leaf: &AspMembershipLeaf) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO asp_membership_leaves
    //                  (leaf_index, leaf, root, ledger) VALUES (?1, ?2, ?3, ?4)",
    //             params![
    //                 i64::from(leaf.index),
    //                 &leaf.leaf,
    //                 &leaf.root,
    //                 i64::from(leaf.ledger),
    //             ],
    //         )
    //         .context("put_asp_membership_leaf")?;
    //     Ok(())
    // }

    // /// Iterates over ASP membership leaves in ascending index order.
    // pub fn iterate_asp_membership_leaves(
    //     &self,
    //     mut callback: impl FnMut(AspMembershipLeaf) -> bool,
    // ) -> anyhow::Result<()> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT leaf_index, leaf, root, ledger
    //                  FROM asp_membership_leaves ORDER BY leaf_index ASC",
    //         )
    //         .context("prepare iterate_asp_membership_leaves")?;
    //     let mut rows = stmt.query([]).context("iterate_asp_membership_leaves")?;
    //     while let Some(row) = rows.next().context("iterate_asp_membership_leaves next")? {
    //         let leaf = AspMembershipLeaf {
    //             index: col_u32(row.get::<_, i64>(0)?, 0)?,
    //             leaf: row.get(1)?,
    //             root: row.get(2)?,
    //             ledger: col_u32(row.get::<_, i64>(3)?, 3)?,
    //         };
    //         if !callback(leaf) {
    //             break;
    //         }
    //     }
    //     Ok(())
    // }

    // /// Returns the first ASP membership leaf matching `leaf_hash`, or `None`.
    // pub fn get_asp_membership_leaf_by_hash(
    //     &self,
    //     leaf_hash: &str,
    // ) -> anyhow::Result<Option<AspMembershipLeaf>> {
    //     let result = self.conn.query_row(
    //         "SELECT leaf_index, leaf, root, ledger
    //              FROM asp_membership_leaves WHERE leaf = ?1 LIMIT 1",
    //         params![leaf_hash],
    //         |row| {
    //             Ok((
    //                 row.get::<_, i64>(0)?,
    //                 row.get::<_, String>(1)?,
    //                 row.get::<_, String>(2)?,
    //                 row.get::<_, i64>(3)?,
    //             ))
    //         },
    //     );
    //     match result {
    //         Ok((idx, leaf, root, ledger)) => Ok(Some(AspMembershipLeaf {
    //             index: col_u32(idx, 0).map_err(|e| anyhow::anyhow!(e))?,
    //             leaf,
    //             root,
    //             ledger: col_u32(ledger, 3).map_err(|e| anyhow::anyhow!(e))?,
    //         })),
    //         Err(SqlError::QueryReturnedNoRows) => Ok(None),
    //         Err(e) => Err(e).context("get_asp_membership_leaf_by_hash"),
    //     }
    // }

    // /// Returns the total number of ASP membership leaves.
    // pub fn count_asp_membership_leaves(&self) -> anyhow::Result<u32> {
    //     let n: i64 = self
    //         .conn
    //         .query_row("SELECT COUNT(*) FROM asp_membership_leaves", [], |row| {
    //             row.get(0)
    //         })
    //         .context("count_asp_membership_leaves")?;
    //     u32::try_from(n).context("count overflow")
    // }

    // /// Inserts or replaces a batch of ASP membership leaves in a single
    // /// transaction.
    // pub fn put_asp_membership_leaves_batch(
    //     &self,
    //     leaves: &[AspMembershipLeaf],
    // ) -> anyhow::Result<()> {
    //     if leaves.is_empty() {
    //         return Ok(());
    //     }
    //     let tx = self
    //         .conn
    //         .unchecked_transaction()
    //         .context("put_asp_membership_leaves_batch begin")?;
    //     {
    //         let mut stmt = tx
    //             .prepare(
    //                 "INSERT OR REPLACE INTO asp_membership_leaves
    //                      (leaf_index, leaf, root, ledger) VALUES (?1, ?2, ?3, ?4)",
    //             )
    //             .context("prepare put_asp_membership_leaves_batch")?;
    //         for leaf in leaves {
    //             stmt.execute(params![
    //                 i64::from(leaf.index),
    //                 &leaf.leaf,
    //                 &leaf.root,
    //                 i64::from(leaf.ledger),
    //             ])
    //             .context("put_asp_membership_leaves_batch execute")?;
    //         }
    //     }
    //     tx.commit()
    //         .context("put_asp_membership_leaves_batch commit")
    // }

    // /// Deletes all ASP membership leaves.
    // pub fn clear_asp_membership_leaves(&self) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM asp_membership_leaves", [])
    //         .context("clear_asp_membership_leaves")?;
    //     Ok(())
    // }

    // // -----------------------------------------------------------------------
    // // user_notes
    // // -----------------------------------------------------------------------

    // /// Inserts or replaces a user note.
    // pub fn put_note(&self, note: &UserNote) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO user_notes
    //                  (id, owner, private_key, blinding, amount, leaf_index,
    //                   created_at, created_at_ledger, spent, spent_at_ledger, is_received)
    //                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    //             params![
    //                 &note.id,
    //                 &note.owner,
    //                 &note.private_key,
    //                 &note.blinding,
    //                 &note.amount,
    //                 note.leaf_index.map(i64::from),
    //                 &note.created_at,
    //                 i64::from(note.created_at_ledger),
    //                 i32::from(note.spent),
    //                 note.spent_at_ledger.map(i64::from),
    //                 i32::from(note.is_received),
    //             ],
    //         )
    //         .context("put_note")?;
    //     Ok(())
    // }

    // /// Returns the note with the given id (commitment hash), or `None`.
    // pub fn get_note(&self, id: &str) -> anyhow::Result<Option<UserNote>> {
    //     let result = self.conn.query_row(
    //         "SELECT id, owner, private_key, blinding, amount, leaf_index,
    //                     created_at, created_at_ledger, spent, spent_at_ledger, is_received
    //              FROM user_notes WHERE id = ?1",
    //         params![id],
    //         map_user_note,
    //     );
    //     match result {
    //         Ok(n) => Ok(Some(n)),
    //         Err(SqlError::QueryReturnedNoRows) => Ok(None),
    //         Err(e) => Err(e).context("get_note"),
    //     }
    // }

    // /// Returns all notes belonging to `owner`.
    // pub fn get_notes_by_owner(&self, owner: &str) -> anyhow::Result<Vec<UserNote>> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT id, owner, private_key, blinding, amount, leaf_index,
    //                         created_at, created_at_ledger, spent, spent_at_ledger, is_received
    //                  FROM user_notes WHERE owner = ?1",
    //         )
    //         .context("prepare get_notes_by_owner")?;
    //     stmt.query_map(params![owner], map_user_note)
    //         .context("get_notes_by_owner")?
    //         .collect::<Result<Vec<_>, _>>()
    //         .context("get_notes_by_owner collect")
    // }

    // /// Returns every note in the store across all owners.
    // pub fn get_all_notes(&self) -> anyhow::Result<Vec<UserNote>> {
    //     let mut stmt = self
    //         .conn
    //         .prepare(
    //             "SELECT id, owner, private_key, blinding, amount, leaf_index,
    //                         created_at, created_at_ledger, spent, spent_at_ledger, is_received
    //                  FROM user_notes",
    //         )
    //         .context("prepare get_all_notes")?;
    //     stmt.query_map([], map_user_note)
    //         .context("get_all_notes")?
    //         .collect::<Result<Vec<_>, _>>()
    //         .context("get_all_notes collect")
    // }

    // /// Deletes the note with the given id.
    // pub fn delete_note(&self, id: &str) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM user_notes WHERE id = ?1", params![id])
    //         .context("delete_note")?;
    //     Ok(())
    // }

    // /// Deletes all notes.
    // pub fn clear_notes(&self) -> anyhow::Result<()> {
    //     self.conn
    //         .execute("DELETE FROM user_notes", [])
    //         .context("clear_notes")?;
    //     Ok(())
    // }

    // -----------------------------------------------------------------------
    // registered_public_keys
    // -----------------------------------------------------------------------

    /// Inserts or replaces a public-key registration.
    pub fn put_public_key(&self, entry: &types::PublicKeyEntry) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO registered_public_keys
                     (address, encryption_key, note_key, public_key, ledger, registered_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    &entry.address,
                    &entry.encryption_key,
                    &entry.note_key,
                    &entry.public_key,
                    i64::from(entry.ledger),
                    &entry.registered_at,
                ],
            )
            .context("put_public_key")?;
        Ok(())
    }

    /// Returns the public-key record for `address`, or `None`.
    pub fn get_public_key(&self, address: &str) -> Result<Option<types::PublicKeyEntry>> {
        let result = self.conn.query_row(
            "SELECT address, encryption_key, note_key, public_key, ledger, registered_at
                 FROM registered_public_keys WHERE address = ?1",
            params![address],
            map_public_key_entry,
        );
        match result {
            Ok(e) => Ok(Some(e)),
            Err(SqlError::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e).context("get_public_key"),
        }
    }

    /// Returns all public keys ordered by ledger descending.
    pub fn get_recent_public_keys(&self, limit: u32) -> Result<Vec<types::PublicKeyEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT address, encryption_key, note_key, public_key, ledger, registered_at
                     FROM registered_public_keys ORDER BY ledger DESC LIMIT ?1",
            )
            .context("prepare get_all_public_keys")?;
        stmt.query_map([limit], map_public_key_entry)
            .context("get_all_public_keys")?
            .collect::<Result<Vec<_>, _>>()
            .context("get_all_public_keys collect")
    }

    /// Returns the total number of registered public keys.
    pub fn count_public_keys(&self) -> Result<u32> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM registered_public_keys", [], |row| {
                row.get(0)
            })
            .context("count_public_keys")?;
        u32::try_from(n).context("count overflow")
    }

    /// Deletes all registered public keys.
    pub fn clear_public_keys(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM registered_public_keys", [])
            .context("clear_public_keys")?;
        Ok(())
    }

    // // -----------------------------------------------------------------------
    // // sync_metadata
    // // -----------------------------------------------------------------------

    // /// Returns the sync metadata for `network`, or `None`.
    // pub fn get_sync_metadata(&self, network: &str) -> anyhow::Result<Option<SyncMetadata>> {
    //     let result = self.conn.query_row(
    //         "SELECT data FROM sync_metadata WHERE network = ?1",
    //         params![network],
    //         |row| row.get::<_, String>(0),
    //     );
    //     match result {
    //         Ok(json) => Ok(Some(
    //             serde_json::from_str(&json).context("deserialising sync_metadata")?,
    //         )),
    //         Err(SqlError::QueryReturnedNoRows) => Ok(None),
    //         Err(e) => Err(e).context("get_sync_metadata"),
    //     }
    // }

    // /// Inserts or replaces sync metadata (keyed by `metadata.network`).
    // pub fn put_sync_metadata(&self, metadata: &SyncMetadata) -> anyhow::Result<()> {
    //     let json = serde_json::to_string(metadata).context("serialising sync_metadata")?;
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO sync_metadata (network, data) VALUES (?1, ?2)",
    //             params![&metadata.network, json],
    //         )
    //         .context("put_sync_metadata")?;
    //     Ok(())
    // }

    // /// Deletes the sync metadata for `network`.
    // pub fn delete_sync_metadata(&self, network: &str) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "DELETE FROM sync_metadata WHERE network = ?1",
    //             params![network],
    //         )
    //         .context("delete_sync_metadata")?;
    //     Ok(())
    // }

    // // -----------------------------------------------------------------------
    // // retention_config
    // // -----------------------------------------------------------------------

    // /// Returns the cached retention config for `rpc_endpoint`, or `None`.
    // pub fn get_retention_config(
    //     &self,
    //     rpc_endpoint: &str,
    // ) -> anyhow::Result<Option<RetentionConfig>> {
    //     let result = self.conn.query_row(
    //         "SELECT rpc_endpoint, window, description, warning_threshold, detected_at
    //              FROM retention_config WHERE rpc_endpoint = ?1",
    //         params![rpc_endpoint],
    //         |row| {
    //             Ok((
    //                 row.get::<_, String>(0)?,
    //                 row.get::<_, i64>(1)?,
    //                 row.get::<_, String>(2)?,
    //                 row.get::<_, i64>(3)?,
    //                 row.get::<_, String>(4)?,
    //             ))
    //         },
    //     );
    //     match result {
    //         Ok((rpc, window, desc, threshold, detected_at)) => Ok(Some(RetentionConfig {
    //             rpc_endpoint: rpc,
    //             window: col_u32(window, 1).map_err(|e| anyhow::anyhow!(e))?,
    //             description: desc,
    //             warning_threshold: col_u32(threshold, 3).map_err(|e| anyhow::anyhow!(e))?,
    //             detected_at,
    //         })),
    //         Err(SqlError::QueryReturnedNoRows) => Ok(None),
    //         Err(e) => Err(e).context("get_retention_config"),
    //     }
    // }

    // /// Inserts or replaces a retention config.
    // pub fn put_retention_config(&self, config: &RetentionConfig) -> anyhow::Result<()> {
    //     self.conn
    //         .execute(
    //             "INSERT OR REPLACE INTO retention_config
    //                  (rpc_endpoint, window, description, warning_threshold, detected_at)
    //                  VALUES (?1, ?2, ?3, ?4, ?5)",
    //             params![
    //                 &config.rpc_endpoint,
    //                 i64::from(config.window),
    //                 &config.description,
    //                 i64::from(config.warning_threshold),
    //                 &config.detected_at,
    //             ],
    //         )
    //         .context("put_retention_config")?;
    //     Ok(())
    // }
}

// ---------------------------------------------------------------------------
// Row-mapping helpers
// ---------------------------------------------------------------------------

/// Converts an `i64` SQLite column to `u32`, returning a rusqlite error on
/// overflow.
fn col_u32(val: i64, col: usize) -> Result<u32, SqlError> {
    u32::try_from(val).map_err(|_| SqlError::IntegralValueOutOfRange(col, val))
}

// fn map_encrypted_output(row: &rusqlite::Row<'_>) -> Result<PoolEncryptedOutput, SqlError> {
//     Ok(PoolEncryptedOutput {
//         commitment: row.get(0)?,
//         leaf_index: col_u32(row.get::<_, i64>(1)?, 1)?,
//         encrypted_output: row.get(2)?,
//         ledger: col_u32(row.get::<_, i64>(3)?, 3)?,
//     })
// }

// fn map_user_note(row: &rusqlite::Row<'_>) -> Result<UserNote, SqlError> {
//     Ok(UserNote {
//         id: row.get(0)?,
//         owner: row.get(1)?,
//         private_key: row.get(2)?,
//         blinding: row.get(3)?,
//         amount: row.get(4)?,
//         leaf_index: row
//             .get::<_, Option<i64>>(5)?
//             .map(|v| col_u32(v, 5))
//             .transpose()?,
//         created_at: row.get(6)?,
//         created_at_ledger: col_u32(row.get::<_, i64>(7)?, 7)?,
//         spent: row.get::<_, i32>(8)? != 0,
//         spent_at_ledger: row
//             .get::<_, Option<i64>>(9)?
//             .map(|v| col_u32(v, 9))
//             .transpose()?,
//         is_received: row.get::<_, i32>(10)? != 0,
//     })
// }

fn map_public_key_entry(row: &rusqlite::Row<'_>) -> Result<types::PublicKeyEntry, SqlError> {
    Ok(types::PublicKeyEntry {
        address: row.get(0)?,
        encryption_key: row.get(1)?,
        note_key: row.get(2)?,
        public_key: row.get(3)?,
        ledger: col_u32(row.get::<_, i64>(4)?, 4)?,
        registered_at: row.get(5)?,
    })
}
