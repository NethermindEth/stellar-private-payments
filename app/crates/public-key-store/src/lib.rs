//! Public key registration store with SQLite-backed persistence.
//! Port of `app/js/state/public-key-store.js` (local state only).
//!
//! Stellar RPC search (`searchByAddress`) deferred to PR-8 (sync-controller).

use std::rc::Rc;
use storage::{Storage, types::PublicKeyEntry};

/// Public key registration store backed by SQLite.
pub struct PublicKeyStore {
    db: Rc<Storage>,
}

impl PublicKeyStore {
    /// Opens the public key store.
    pub fn open(db: Rc<Storage>) -> Self {
        Self { db }
    }

    /// Stores a public key registration (new format: separate encryption + note
    /// keys).
    ///
    /// `encryption_key` is an X25519 key (hex). `note_key` is a BN254 key
    /// (hex). Both must already be `0x`-prefixed hex strings (caller
    /// normalizes).
    pub fn store_registration(
        &self,
        address: &str,
        encryption_key: &str,
        note_key: &str,
        ledger: u32,
        registered_at: &str,
    ) -> anyhow::Result<()> {
        self.db.put_public_key(&PublicKeyEntry {
            address: address.to_owned(),
            encryption_key: encryption_key.to_owned(),
            note_key: note_key.to_owned(),
            public_key: encryption_key.to_owned(),
            ledger,
            registered_at: registered_at.to_owned(),
        })
    }

    /// Returns the registration for `address`, or `None`.
    pub fn get_by_address(&self, address: &str) -> anyhow::Result<Option<PublicKeyEntry>> {
        self.db.get_public_key(address)
    }

    /// Returns all registrations ordered by ledger descending (most recent
    /// first).
    pub fn get_all(&self) -> anyhow::Result<Vec<PublicKeyEntry>> {
        self.db.get_all_public_keys()
    }

    /// Returns the number of registered public keys.
    pub fn count(&self) -> anyhow::Result<u32> {
        self.db.count_public_keys()
    }

    /// Clears all public key registrations.
    pub fn clear(&self) -> anyhow::Result<()> {
        self.db.clear_public_keys()
    }
}
