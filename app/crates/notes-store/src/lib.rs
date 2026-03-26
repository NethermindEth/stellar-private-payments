//! User note (UTXO) storage with SQLite-backed persistence.
//! Port of `app/js/state/notes-store.js` (storage only).
//!
//! Key derivation from Freighter signatures stays in JS. Rust handles:
//! save, get, mark spent, delete, clear, balance computation.

use storage::{Storage, types::UserNote};
use utils::normalize_hex;

/// Parameters for creating a new note.
pub struct NewNote<'a> {
    /// Commitment hash (hex, used as primary key).
    pub commitment: &'a str,
    /// Owner Stellar address.
    pub owner: &'a str,
    /// Note private key (hex).
    pub private_key: &'a str,
    /// Blinding factor (hex).
    pub blinding: &'a str,
    /// Amount as decimal string.
    pub amount: &'a str,
    /// Leaf index in pool tree; `None` until mined.
    pub leaf_index: Option<u32>,
    /// Ledger when created.
    pub ledger: u32,
    /// ISO-8601 creation timestamp.
    pub created_at: &'a str,
    /// `true` if received via transfer (discovered by scanning).
    pub is_received: bool,
}

/// User note store backed by SQLite.
pub struct NotesStore {
    db: Storage,
}

impl NotesStore {
    /// Opens the notes store.
    pub fn open(db: Storage) -> Self {
        Self { db }
    }

    /// Saves a new note. Commitment is normalized to lowercase `0x`-prefixed
    /// hex.
    pub fn save_note(&self, n: &NewNote<'_>) -> anyhow::Result<UserNote> {
        let note = UserNote {
            id: normalize_hex(n.commitment).to_lowercase(),
            owner: n.owner.to_owned(),
            private_key: n.private_key.to_owned(),
            blinding: n.blinding.to_owned(),
            amount: n.amount.to_owned(),
            leaf_index: n.leaf_index,
            created_at: n.created_at.to_owned(),
            created_at_ledger: n.ledger,
            spent: false,
            spent_at_ledger: None,
            is_received: n.is_received,
        };
        self.db.put_note(&note)?;
        Ok(note)
    }

    /// Marks a note as spent. Returns `true` if the note existed.
    pub fn mark_spent(&self, commitment: &str, ledger: u32) -> anyhow::Result<bool> {
        let id = normalize_hex(commitment).to_lowercase();
        let Some(mut note) = self.db.get_note(&id)? else {
            return Ok(false);
        };
        note.spent = true;
        note.spent_at_ledger = Some(ledger);
        self.db.put_note(&note)?;
        Ok(true)
    }

    /// Returns the note for `commitment`, or `None`.
    pub fn get_by_commitment(&self, commitment: &str) -> anyhow::Result<Option<UserNote>> {
        let id = normalize_hex(commitment).to_lowercase();
        self.db.get_note(&id)
    }

    /// Returns all notes for `owner`.
    pub fn get_by_owner(&self, owner: &str) -> anyhow::Result<Vec<UserNote>> {
        self.db.get_notes_by_owner(owner)
    }

    /// Returns unspent notes for `owner`.
    pub fn get_unspent(&self, owner: &str) -> anyhow::Result<Vec<UserNote>> {
        let notes = self.db.get_notes_by_owner(owner)?;
        Ok(notes.into_iter().filter(|n| !n.spent).collect())
    }

    /// Returns the total balance of unspent notes for `owner`. Each note
    /// amount is a decimal string; this sums them.
    pub fn get_balance(&self, owner: &str) -> anyhow::Result<u128> {
        let notes = self.get_unspent(owner)?;
        let mut total: u128 = 0;
        for note in &notes {
            let amt: u128 = note
                .amount
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid note amount '{}': {e}", note.amount))?;
            total = total
                .checked_add(amt)
                .ok_or_else(|| anyhow::anyhow!("balance overflow"))?;
        }
        Ok(total)
    }

    /// Returns all notes across all owners.
    pub fn get_all(&self) -> anyhow::Result<Vec<UserNote>> {
        self.db.get_all_notes()
    }

    /// Deletes a note by commitment.
    pub fn delete(&self, commitment: &str) -> anyhow::Result<()> {
        let id = normalize_hex(commitment).to_lowercase();
        self.db.delete_note(&id)
    }

    /// Clears all notes.
    pub fn clear(&self) -> anyhow::Result<()> {
        self.db.clear_notes()
    }
}
