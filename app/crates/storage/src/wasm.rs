//! WASM SQLite backend using `sqlite-wasm-rs` FFI.

use anyhow::{Context, bail};
use sqlite_wasm_rs as ffi;
use std::{
    ffi::{CStr, CString},
    ptr,
};

use crate::{
    SCHEMA,
    types::{
        AspMembershipLeaf, PoolEncryptedOutput, PoolLeaf, PoolNullifier, PublicKeyEntry,
        RetentionConfig, SyncMetadata, UserNote,
    },
};

struct Conn(*mut ffi::sqlite3);

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_close(self.0) };
    }
}

struct Stmt {
    ptr: *mut ffi::sqlite3_stmt,
    db: *mut ffi::sqlite3,
    bound_strings: std::cell::RefCell<Vec<CString>>,
}

impl Drop for Stmt {
    fn drop(&mut self) {
        unsafe { ffi::sqlite3_finalize(self.ptr) };
    }
}

fn errmsg(db: *mut ffi::sqlite3) -> String {
    unsafe {
        let p = ffi::sqlite3_errmsg(db);
        if p.is_null() {
            return String::from("unknown sqlite error");
        }
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

fn cstr(s: &str) -> anyhow::Result<CString> {
    CString::new(s).context("null byte in string")
}

impl Conn {
    fn open(path: &str) -> anyhow::Result<Self> {
        let cpath = cstr(path)?;
        let mut db = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_open_v2(
                cpath.as_ptr(),
                &mut db,
                ffi::SQLITE_OPEN_READWRITE | ffi::SQLITE_OPEN_CREATE,
                ptr::null(),
            )
        };
        if rc != ffi::SQLITE_OK {
            let msg = if db.is_null() {
                String::from("sqlite3_open_v2 failed")
            } else {
                let m = errmsg(db);
                unsafe { ffi::sqlite3_close(db) };
                m
            };
            bail!("{msg}");
        }
        Ok(Self(db))
    }

    fn exec(&self, sql: &str) -> anyhow::Result<()> {
        let csql = cstr(sql)?;
        let rc = unsafe {
            ffi::sqlite3_exec(
                self.0,
                csql.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != ffi::SQLITE_OK {
            bail!("{}", errmsg(self.0));
        }
        Ok(())
    }

    fn prepare(&self, sql: &str) -> anyhow::Result<Stmt> {
        let csql = cstr(sql)?;
        let mut raw = ptr::null_mut();
        let rc = unsafe {
            ffi::sqlite3_prepare_v2(self.0, csql.as_ptr(), -1, &mut raw, ptr::null_mut())
        };
        if rc != ffi::SQLITE_OK {
            bail!("{}", errmsg(self.0));
        }
        Ok(Stmt {
            ptr: raw,
            db: self.0,
            bound_strings: std::cell::RefCell::new(Vec::new()),
        })
    }
}

impl Stmt {
    fn bind_i64(&self, idx: i32, val: i64) -> anyhow::Result<()> {
        let rc = unsafe { ffi::sqlite3_bind_int64(self.ptr, idx, val) };
        if rc != ffi::SQLITE_OK {
            bail!("{}", errmsg(self.db));
        }
        Ok(())
    }

    fn bind_text(&self, idx: i32, val: &str) -> anyhow::Result<()> {
        let c = cstr(val)?;
        let ptr = c.as_ptr();
        self.bound_strings.borrow_mut().push(c);
        let rc = unsafe { ffi::sqlite3_bind_text(self.ptr, idx, ptr, -1, None) };
        if rc != ffi::SQLITE_OK {
            bail!("{}", errmsg(self.db));
        }
        Ok(())
    }

    fn bind_null(&self, idx: i32) -> anyhow::Result<()> {
        let rc = unsafe { ffi::sqlite3_bind_null(self.ptr, idx) };
        if rc != ffi::SQLITE_OK {
            bail!("{}", errmsg(self.db));
        }
        Ok(())
    }

    fn bind_opt_i64(&self, idx: i32, val: Option<i64>) -> anyhow::Result<()> {
        match val {
            Some(v) => self.bind_i64(idx, v),
            None => self.bind_null(idx),
        }
    }

    fn step_row(&self) -> anyhow::Result<bool> {
        let rc = unsafe { ffi::sqlite3_step(self.ptr) };
        match rc {
            ffi::SQLITE_ROW => Ok(true),
            ffi::SQLITE_DONE => Ok(false),
            _ => bail!("{}", errmsg(self.db)),
        }
    }

    fn reset(&self) -> anyhow::Result<()> {
        unsafe { ffi::sqlite3_reset(self.ptr) };
        self.bound_strings.borrow_mut().clear();
        Ok(())
    }

    fn col_i64(&self, idx: i32) -> i64 {
        unsafe { ffi::sqlite3_column_int64(self.ptr, idx) }
    }

    fn col_text(&self, idx: i32) -> String {
        unsafe {
            let p = ffi::sqlite3_column_text(self.ptr, idx);
            if p.is_null() {
                return String::new();
            }
            CStr::from_ptr(p.cast()).to_string_lossy().into_owned()
        }
    }

    fn col_is_null(&self, idx: i32) -> bool {
        unsafe { ffi::sqlite3_column_type(self.ptr, idx) == ffi::SQLITE_NULL }
    }

    fn col_opt_i64(&self, idx: i32) -> Option<i64> {
        if self.col_is_null(idx) {
            None
        } else {
            Some(self.col_i64(idx))
        }
    }
}

fn col_u32(val: i64) -> anyhow::Result<u32> {
    u32::try_from(val).context("column value out of u32 range")
}

/// SQLite-backed storage
pub struct Storage {
    conn: Conn,
}

impl Storage {
    /// Opens (if not exists, creates) a SQLite database at `path` and applies
    /// the schema.
    pub fn open(path: &str) -> anyhow::Result<Self> {
        let conn = Conn::open(path)?;
        conn.exec(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Opens an in-memory database.
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Self::open(":memory:")
    }

    /// Inserts or replaces a pool leaf.
    pub fn put_pool_leaf(&self, leaf: &PoolLeaf) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO pool_leaves (leaf_index, commitment, ledger) VALUES (?1, ?2, ?3)",
        )?;
        s.bind_i64(1, i64::from(leaf.index))?;
        s.bind_text(2, &leaf.commitment)?;
        s.bind_i64(3, i64::from(leaf.ledger))?;
        s.step_row()?;
        Ok(())
    }

    /// Iterates pool leaves in ascending index order.
    pub fn iterate_pool_leaves(&self, mut cb: impl FnMut(PoolLeaf) -> bool) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "SELECT leaf_index, commitment, ledger FROM pool_leaves ORDER BY leaf_index ASC",
        )?;
        while s.step_row()? {
            let leaf = PoolLeaf {
                index: col_u32(s.col_i64(0))?,
                commitment: s.col_text(1),
                ledger: col_u32(s.col_i64(2))?,
            };
            if !cb(leaf) {
                break;
            }
        }
        Ok(())
    }

    /// Returns the total number of pool leaves.
    pub fn count_pool_leaves(&self) -> anyhow::Result<u32> {
        let s = self.conn.prepare("SELECT COUNT(*) FROM pool_leaves")?;
        s.step_row()?;
        col_u32(s.col_i64(0))
    }

    /// Inserts or replaces a batch of pool leaves in a single transaction.
    pub fn put_pool_leaves_batch(&self, leaves: &[PoolLeaf]) -> anyhow::Result<()> {
        if leaves.is_empty() {
            return Ok(());
        }
        self.conn.exec("BEGIN")?;
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO pool_leaves (leaf_index, commitment, ledger) VALUES (?1, ?2, ?3)",
        )?;
        for leaf in leaves {
            s.bind_i64(1, i64::from(leaf.index))?;
            s.bind_text(2, &leaf.commitment)?;
            s.bind_i64(3, i64::from(leaf.ledger))?;
            s.step_row()?;
            s.reset()?;
        }
        drop(s);
        self.conn.exec("COMMIT")
    }

    /// Deletes all pool leaves.
    pub fn clear_pool_leaves(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM pool_leaves")
    }

    /// Inserts or replaces a nullifier record.
    pub fn put_nullifier(&self, nullifier: &PoolNullifier) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO pool_nullifiers (nullifier, ledger) VALUES (?1, ?2)",
        )?;
        s.bind_text(1, &nullifier.nullifier)?;
        s.bind_i64(2, i64::from(nullifier.ledger))?;
        s.step_row()?;
        Ok(())
    }

    /// Returns the nullifier record, or `None` if unspent.
    pub fn get_nullifier(&self, nullifier: &str) -> anyhow::Result<Option<PoolNullifier>> {
        let s = self
            .conn
            .prepare("SELECT nullifier, ledger FROM pool_nullifiers WHERE nullifier = ?1")?;
        s.bind_text(1, nullifier)?;
        if !s.step_row()? {
            return Ok(None);
        }
        Ok(Some(PoolNullifier {
            nullifier: s.col_text(0),
            ledger: col_u32(s.col_i64(1))?,
        }))
    }

    /// Returns the total number of spent nullifiers.
    pub fn count_nullifiers(&self) -> anyhow::Result<u32> {
        let s = self.conn.prepare("SELECT COUNT(*) FROM pool_nullifiers")?;
        s.step_row()?;
        col_u32(s.col_i64(0))
    }

    /// Deletes all nullifiers.
    pub fn clear_nullifiers(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM pool_nullifiers")
    }

    /// Inserts or replaces an encrypted output.
    pub fn put_encrypted_output(&self, output: &PoolEncryptedOutput) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO pool_encrypted_outputs
             (commitment, leaf_index, encrypted_output, ledger) VALUES (?1, ?2, ?3, ?4)",
        )?;
        s.bind_text(1, &output.commitment)?;
        s.bind_i64(2, i64::from(output.leaf_index))?;
        s.bind_text(3, &output.encrypted_output)?;
        s.bind_i64(4, i64::from(output.ledger))?;
        s.step_row()?;
        Ok(())
    }

    /// Returns all encrypted outputs.
    pub fn get_all_encrypted_outputs(&self) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
        let s = self.conn.prepare(
            "SELECT commitment, leaf_index, encrypted_output, ledger FROM pool_encrypted_outputs",
        )?;
        let mut out = Vec::new();
        while s.step_row()? {
            out.push(PoolEncryptedOutput {
                commitment: s.col_text(0),
                leaf_index: col_u32(s.col_i64(1))?,
                encrypted_output: s.col_text(2),
                ledger: col_u32(s.col_i64(3))?,
            });
        }
        Ok(out)
    }

    /// Returns encrypted outputs with `ledger >= from_ledger`.
    pub fn get_encrypted_outputs_from(
        &self,
        from_ledger: u32,
    ) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
        let s = self.conn.prepare(
            "SELECT commitment, leaf_index, encrypted_output, ledger
             FROM pool_encrypted_outputs WHERE ledger >= ?1",
        )?;
        s.bind_i64(1, i64::from(from_ledger))?;
        let mut out = Vec::new();
        while s.step_row()? {
            out.push(PoolEncryptedOutput {
                commitment: s.col_text(0),
                leaf_index: col_u32(s.col_i64(1))?,
                encrypted_output: s.col_text(2),
                ledger: col_u32(s.col_i64(3))?,
            });
        }
        Ok(out)
    }

    /// Deletes all encrypted outputs.
    pub fn clear_encrypted_outputs(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM pool_encrypted_outputs")
    }

    /// Inserts or replaces an ASP membership leaf.
    pub fn put_asp_membership_leaf(&self, leaf: &AspMembershipLeaf) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO asp_membership_leaves
             (leaf_index, leaf, root, ledger) VALUES (?1, ?2, ?3, ?4)",
        )?;
        s.bind_i64(1, i64::from(leaf.index))?;
        s.bind_text(2, &leaf.leaf)?;
        s.bind_text(3, &leaf.root)?;
        s.bind_i64(4, i64::from(leaf.ledger))?;
        s.step_row()?;
        Ok(())
    }

    /// Iterates ASP membership leaves in ascending index order.
    pub fn iterate_asp_membership_leaves(
        &self,
        mut cb: impl FnMut(AspMembershipLeaf) -> bool,
    ) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "SELECT leaf_index, leaf, root, ledger FROM asp_membership_leaves ORDER BY leaf_index ASC",
        )?;
        while s.step_row()? {
            let leaf = AspMembershipLeaf {
                index: col_u32(s.col_i64(0))?,
                leaf: s.col_text(1),
                root: s.col_text(2),
                ledger: col_u32(s.col_i64(3))?,
            };
            if !cb(leaf) {
                break;
            }
        }
        Ok(())
    }

    /// Returns the first ASP membership leaf matching `leaf_hash`, or `None`.
    pub fn get_asp_membership_leaf_by_hash(
        &self,
        leaf_hash: &str,
    ) -> anyhow::Result<Option<AspMembershipLeaf>> {
        let s = self.conn.prepare(
            "SELECT leaf_index, leaf, root, ledger FROM asp_membership_leaves WHERE leaf = ?1 LIMIT 1",
        )?;
        s.bind_text(1, leaf_hash)?;
        if !s.step_row()? {
            return Ok(None);
        }
        Ok(Some(AspMembershipLeaf {
            index: col_u32(s.col_i64(0))?,
            leaf: s.col_text(1),
            root: s.col_text(2),
            ledger: col_u32(s.col_i64(3))?,
        }))
    }

    /// Returns the total number of ASP membership leaves.
    pub fn count_asp_membership_leaves(&self) -> anyhow::Result<u32> {
        let s = self
            .conn
            .prepare("SELECT COUNT(*) FROM asp_membership_leaves")?;
        s.step_row()?;
        col_u32(s.col_i64(0))
    }

    /// Inserts or replaces a batch of ASP membership leaves in a single
    /// transaction.
    pub fn put_asp_membership_leaves_batch(
        &self,
        leaves: &[AspMembershipLeaf],
    ) -> anyhow::Result<()> {
        if leaves.is_empty() {
            return Ok(());
        }
        self.conn.exec("BEGIN")?;
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO asp_membership_leaves
             (leaf_index, leaf, root, ledger) VALUES (?1, ?2, ?3, ?4)",
        )?;
        for leaf in leaves {
            s.bind_i64(1, i64::from(leaf.index))?;
            s.bind_text(2, &leaf.leaf)?;
            s.bind_text(3, &leaf.root)?;
            s.bind_i64(4, i64::from(leaf.ledger))?;
            s.step_row()?;
            s.reset()?;
        }
        drop(s);
        self.conn.exec("COMMIT")
    }

    /// Deletes all ASP membership leaves.
    pub fn clear_asp_membership_leaves(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM asp_membership_leaves")
    }

    /// Inserts or replaces a user note.
    pub fn put_note(&self, note: &UserNote) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO user_notes
             (id, owner, private_key, blinding, amount, leaf_index,
              created_at, created_at_ledger, spent, spent_at_ledger, is_received)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        s.bind_text(1, &note.id)?;
        s.bind_text(2, &note.owner)?;
        s.bind_text(3, &note.private_key)?;
        s.bind_text(4, &note.blinding)?;
        s.bind_text(5, &note.amount)?;
        s.bind_opt_i64(6, note.leaf_index.map(i64::from))?;
        s.bind_text(7, &note.created_at)?;
        s.bind_i64(8, i64::from(note.created_at_ledger))?;
        s.bind_i64(9, i64::from(i32::from(note.spent)))?;
        s.bind_opt_i64(10, note.spent_at_ledger.map(i64::from))?;
        s.bind_i64(11, i64::from(i32::from(note.is_received)))?;
        s.step_row()?;
        Ok(())
    }

    /// Returns the note with the given id, or `None`.
    pub fn get_note(&self, id: &str) -> anyhow::Result<Option<UserNote>> {
        let s = self.conn.prepare(
            "SELECT id, owner, private_key, blinding, amount, leaf_index,
                    created_at, created_at_ledger, spent, spent_at_ledger, is_received
             FROM user_notes WHERE id = ?1",
        )?;
        s.bind_text(1, id)?;
        if !s.step_row()? {
            return Ok(None);
        }
        Ok(Some(read_note(&s)?))
    }

    /// Returns all notes belonging to `owner`.
    pub fn get_notes_by_owner(&self, owner: &str) -> anyhow::Result<Vec<UserNote>> {
        let s = self.conn.prepare(
            "SELECT id, owner, private_key, blinding, amount, leaf_index,
                    created_at, created_at_ledger, spent, spent_at_ledger, is_received
             FROM user_notes WHERE owner = ?1",
        )?;
        s.bind_text(1, owner)?;
        let mut out = Vec::new();
        while s.step_row()? {
            out.push(read_note(&s)?);
        }
        Ok(out)
    }

    /// Returns every note in the store.
    pub fn get_all_notes(&self) -> anyhow::Result<Vec<UserNote>> {
        let s = self.conn.prepare(
            "SELECT id, owner, private_key, blinding, amount, leaf_index,
                    created_at, created_at_ledger, spent, spent_at_ledger, is_received
             FROM user_notes",
        )?;
        let mut out = Vec::new();
        while s.step_row()? {
            out.push(read_note(&s)?);
        }
        Ok(out)
    }

    /// Deletes the note with the given id.
    pub fn delete_note(&self, id: &str) -> anyhow::Result<()> {
        let s = self.conn.prepare("DELETE FROM user_notes WHERE id = ?1")?;
        s.bind_text(1, id)?;
        s.step_row()?;
        Ok(())
    }

    /// Deletes all notes.
    pub fn clear_notes(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM user_notes")
    }

    /// Inserts or replaces a public-key registration.
    pub fn put_public_key(&self, entry: &PublicKeyEntry) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO registered_public_keys
             (address, encryption_key, note_key, public_key, ledger, registered_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )?;
        s.bind_text(1, &entry.address)?;
        s.bind_text(2, &entry.encryption_key)?;
        s.bind_text(3, &entry.note_key)?;
        s.bind_text(4, &entry.public_key)?;
        s.bind_i64(5, i64::from(entry.ledger))?;
        s.bind_text(6, &entry.registered_at)?;
        s.step_row()?;
        Ok(())
    }

    /// Returns the public-key record for `address`, or `None`.
    pub fn get_public_key(&self, address: &str) -> anyhow::Result<Option<PublicKeyEntry>> {
        let s = self.conn.prepare(
            "SELECT address, encryption_key, note_key, public_key, ledger, registered_at
             FROM registered_public_keys WHERE address = ?1",
        )?;
        s.bind_text(1, address)?;
        if !s.step_row()? {
            return Ok(None);
        }
        Ok(Some(PublicKeyEntry {
            address: s.col_text(0),
            encryption_key: s.col_text(1),
            note_key: s.col_text(2),
            public_key: s.col_text(3),
            ledger: col_u32(s.col_i64(4))?,
            registered_at: s.col_text(5),
        }))
    }

    /// Returns all public keys ordered by ledger descending.
    pub fn get_all_public_keys(&self) -> anyhow::Result<Vec<PublicKeyEntry>> {
        let s = self.conn.prepare(
            "SELECT address, encryption_key, note_key, public_key, ledger, registered_at
             FROM registered_public_keys ORDER BY ledger DESC",
        )?;
        let mut out = Vec::new();
        while s.step_row()? {
            out.push(PublicKeyEntry {
                address: s.col_text(0),
                encryption_key: s.col_text(1),
                note_key: s.col_text(2),
                public_key: s.col_text(3),
                ledger: col_u32(s.col_i64(4))?,
                registered_at: s.col_text(5),
            });
        }
        Ok(out)
    }

    /// Returns the total number of registered public keys.
    pub fn count_public_keys(&self) -> anyhow::Result<u32> {
        let s = self
            .conn
            .prepare("SELECT COUNT(*) FROM registered_public_keys")?;
        s.step_row()?;
        col_u32(s.col_i64(0))
    }

    /// Deletes all registered public keys.
    pub fn clear_public_keys(&self) -> anyhow::Result<()> {
        self.conn.exec("DELETE FROM registered_public_keys")
    }

    /// Returns the sync metadata for `network`, or `None`.
    pub fn get_sync_metadata(&self, network: &str) -> anyhow::Result<Option<SyncMetadata>> {
        let s = self
            .conn
            .prepare("SELECT data FROM sync_metadata WHERE network = ?1")?;
        s.bind_text(1, network)?;
        if !s.step_row()? {
            return Ok(None);
        }
        let json = s.col_text(0);
        Ok(Some(
            serde_json::from_str(&json).context("deserialising sync_metadata")?,
        ))
    }

    /// Inserts or replaces sync metadata.
    pub fn put_sync_metadata(&self, metadata: &SyncMetadata) -> anyhow::Result<()> {
        let json = serde_json::to_string(metadata).context("serialising sync_metadata")?;
        let s = self
            .conn
            .prepare("INSERT OR REPLACE INTO sync_metadata (network, data) VALUES (?1, ?2)")?;
        s.bind_text(1, &metadata.network)?;
        s.bind_text(2, &json)?;
        s.step_row()?;
        Ok(())
    }

    /// Deletes the sync metadata for `network`.
    pub fn delete_sync_metadata(&self, network: &str) -> anyhow::Result<()> {
        let s = self
            .conn
            .prepare("DELETE FROM sync_metadata WHERE network = ?1")?;
        s.bind_text(1, network)?;
        s.step_row()?;
        Ok(())
    }

    /// Returns the cached retention config for `rpc_endpoint`, or `None`.
    pub fn get_retention_config(
        &self,
        rpc_endpoint: &str,
    ) -> anyhow::Result<Option<RetentionConfig>> {
        let s = self.conn.prepare(
            "SELECT rpc_endpoint, window, description, warning_threshold, detected_at
             FROM retention_config WHERE rpc_endpoint = ?1",
        )?;
        s.bind_text(1, rpc_endpoint)?;
        if !s.step_row()? {
            return Ok(None);
        }
        Ok(Some(RetentionConfig {
            rpc_endpoint: s.col_text(0),
            window: col_u32(s.col_i64(1))?,
            description: s.col_text(2),
            warning_threshold: col_u32(s.col_i64(3))?,
            detected_at: s.col_text(4),
        }))
    }

    /// Inserts or replaces a retention config.
    pub fn put_retention_config(&self, config: &RetentionConfig) -> anyhow::Result<()> {
        let s = self.conn.prepare(
            "INSERT OR REPLACE INTO retention_config
             (rpc_endpoint, window, description, warning_threshold, detected_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        s.bind_text(1, &config.rpc_endpoint)?;
        s.bind_i64(2, i64::from(config.window))?;
        s.bind_text(3, &config.description)?;
        s.bind_i64(4, i64::from(config.warning_threshold))?;
        s.bind_text(5, &config.detected_at)?;
        s.step_row()?;
        Ok(())
    }

    /// Deletes all rows from every table.
    pub fn clear_all(&self) -> anyhow::Result<()> {
        self.conn.exec(
            "DELETE FROM pool_leaves;
             DELETE FROM pool_nullifiers;
             DELETE FROM pool_encrypted_outputs;
             DELETE FROM asp_membership_leaves;
             DELETE FROM user_notes;
             DELETE FROM registered_public_keys;
             DELETE FROM sync_metadata;
             DELETE FROM retention_config;",
        )
    }
}

fn read_note(s: &Stmt) -> anyhow::Result<UserNote> {
    Ok(UserNote {
        id: s.col_text(0),
        owner: s.col_text(1),
        private_key: s.col_text(2),
        blinding: s.col_text(3),
        amount: s.col_text(4),
        leaf_index: s.col_opt_i64(5).map(col_u32).transpose()?,
        created_at: s.col_text(6),
        created_at_ledger: col_u32(s.col_i64(7))?,
        spent: s.col_i64(8) != 0,
        spent_at_ledger: s.col_opt_i64(9).map(col_u32).transpose()?,
        is_received: s.col_i64(10) != 0,
    })
}
