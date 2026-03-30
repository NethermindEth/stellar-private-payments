//! WASM state bridge — exposes all Rust stores to the frontend via
//! `wasm-bindgen`.
//!
//! Replaces `app/js/state/db.js` and the individual JS store modules.
//! RPC / wallet logic stays in JS; this crate handles persistent storage,
//! Merkle trees, note scanning, and utility conversions.

use std::rc::Rc;

use asp_store::AspStore;
use note_scanner::ScanKeys;
use notes_store::{NewNote, NotesStore};
use pool_store::PoolStore;
use public_key_store::PublicKeyStore;
use storage::Storage;
use wasm_bindgen::prelude::*;

/// Database file path for SQLite in WASM (OPFS-backed when available).
const DB_PATH: &str = "poolstellar.db";

/// Converts an `anyhow::Error` to `JsValue`.
fn err(e: anyhow::Error) -> JsValue {
    JsValue::from_str(&format!("{e:#}"))
}

// ── Stellar event helpers ──────────────────────────────────────────────

/// A Stellar contract event as serialised from the JS SDK.
#[derive(serde::Deserialize)]
struct StellarEvent {
    topic: Option<Vec<serde_json::Value>>,
    value: Option<serde_json::Value>,
    ledger: Option<u32>,
}

/// Normalises a Stellar U256 / hex JSON value to `0x`-prefixed lowercase hex.
fn normalize_value_to_hex(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return None;
            }
            if s.starts_with("0x") || s.starts_with("0X") {
                Some(s.to_lowercase())
            } else {
                Some(format!("0x{}", s.to_lowercase()))
            }
        }
        serde_json::Value::Number(n) => n.as_u64().map(|i| format!("0x{i:064x}")),
        serde_json::Value::Object(obj) if obj.contains_key("hi") && obj.contains_key("lo") => {
            let hi = parse_u128(&obj["hi"]).unwrap_or(0);
            let lo = parse_u128(&obj["lo"]).unwrap_or(0);
            Some(format!("0x{hi:032x}{lo:032x}"))
        }
        _ => None,
    }
}

/// Parses a JSON number or string into `u128`.
fn parse_u128(v: &serde_json::Value) -> Option<u128> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        serde_json::Value::String(s) => s.parse::<u128>().ok(),
        _ => None,
    }
}

/// Converts a JSON value (string or byte-array) to a hex string.
fn value_to_hex_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(arr) => {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|n| n.as_u64().and_then(|i| u8::try_from(i).ok()))
                .collect();
            if bytes.is_empty() {
                None
            } else {
                Some(utils::bytes_to_hex(&bytes))
            }
        }
        _ => None,
    }
}

/// Initialize the WASM module (panic hook for browser console).
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Merkle proof exported to JS with the same property API as the prover
/// crate's `MerkleProof`.
#[wasm_bindgen]
pub struct WasmMerkleProof {
    elements: Vec<u8>,
    indices: u64,
    root_bytes: Vec<u8>,
}

#[wasm_bindgen]
impl WasmMerkleProof {
    /// Sibling hashes from leaf to root (LE bytes, `depth * 32`).
    #[wasm_bindgen(getter)]
    pub fn path_elements(&self) -> Vec<u8> {
        self.elements.clone()
    }

    /// Direction bits packed into a `u64`.
    #[wasm_bindgen(getter)]
    pub fn path_indices(&self) -> u64 {
        self.indices
    }

    /// Tree root at proof time (LE bytes).
    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        self.root_bytes.clone()
    }
}

/// Unified state manager owning all stores with a shared SQLite connection.
#[wasm_bindgen]
pub struct StateManager {
    pool: PoolStore,
    asp: AspStore,
    notes: NotesStore,
    public_keys: PublicKeyStore,
    db: Rc<Storage>,
}

#[wasm_bindgen]
impl StateManager {
    /// Opens the database and initializes all stores.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<StateManager, JsValue> {
        let db = Rc::new(Storage::open(DB_PATH).map_err(err)?);
        let pool = PoolStore::open(Rc::clone(&db)).map_err(err)?;
        let asp = AspStore::open(Rc::clone(&db)).map_err(err)?;
        let notes = NotesStore::open(Rc::clone(&db));
        let public_keys = PublicKeyStore::open(Rc::clone(&db));
        Ok(Self {
            pool,
            asp,
            notes,
            public_keys,
            db,
        })
    }

    // ── Pool ────────────────────────────────────────────────────────────

    /// Persists a new commitment and inserts it into the pool Merkle tree.
    pub fn process_new_commitment(
        &mut self,
        commitment: &str,
        index: u32,
        encrypted_output: &str,
        ledger: u32,
    ) -> Result<(), JsValue> {
        self.pool
            .process_new_commitment(commitment, index, encrypted_output, ledger)
            .map_err(err)
    }

    /// Persists a spent nullifier.
    pub fn process_new_nullifier(&self, nullifier: &str, ledger: u32) -> Result<(), JsValue> {
        self.pool
            .process_new_nullifier(nullifier, ledger)
            .map_err(err)
    }

    /// Returns the pool Merkle root as LE bytes.
    pub fn get_pool_root(&self) -> Vec<u8> {
        self.pool.root().to_vec()
    }

    /// Returns the pool Merkle root as `0x`-prefixed BE hex.
    pub fn get_pool_root_hex(&self) -> String {
        self.pool.root_hex()
    }

    /// Returns the Merkle proof for a pool leaf.
    pub fn get_pool_merkle_proof(&self, leaf_index: u32) -> Result<WasmMerkleProof, JsValue> {
        let proof = self.pool.get_proof(leaf_index).map_err(err)?;
        Ok(WasmMerkleProof {
            elements: proof.path_elements,
            indices: proof.path_indices,
            root_bytes: proof.root.to_vec(),
        })
    }

    /// Returns `true` if the nullifier has been spent.
    pub fn is_nullifier_spent(&self, nullifier: &str) -> Result<bool, JsValue> {
        Ok(self.pool.get_nullifier(nullifier).map_err(err)?.is_some())
    }

    /// Returns the next pool leaf insertion index.
    pub fn get_pool_next_index(&self) -> u32 {
        self.pool.next_index()
    }

    /// Returns the number of pool leaves in the database.
    pub fn get_pool_leaf_count(&self) -> Result<u32, JsValue> {
        self.pool.leaf_count().map_err(err)
    }

    /// Rebuilds the pool Merkle tree from persisted leaves.
    pub fn rebuild_pool_tree(&mut self) -> Result<u32, JsValue> {
        self.pool.rebuild_tree().map_err(err)
    }

    /// Returns encrypted outputs as JSON, optionally filtered by ledger.
    pub fn get_encrypted_outputs(&self, from_ledger: Option<u32>) -> Result<String, JsValue> {
        let outputs = self.pool.get_encrypted_outputs(from_ledger).map_err(err)?;
        serde_json::to_string(&outputs).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    // ── Batch event processing (replaces JS pool-store / asp-membership-store) ─

    /// Processes a batch of Pool contract events (JSON array from the Stellar
    /// SDK).  Handles `NewCommitment*` and `NewNullifier*` topics.
    /// Returns JSON `{ "commitments": N, "nullifiers": N }`.
    pub fn process_pool_events(
        &mut self,
        events_json: &str,
        default_ledger: u32,
    ) -> Result<String, JsValue> {
        let events: Vec<StellarEvent> = serde_json::from_str(events_json)
            .map_err(|e| JsValue::from_str(&format!("invalid pool events JSON: {e}")))?;

        let mut commitments = 0u32;
        let mut nullifiers = 0u32;

        for event in &events {
            let topic0 = event
                .topic
                .as_ref()
                .and_then(|t| t.first())
                .and_then(|v| v.as_str());
            let ledger = event.ledger.unwrap_or(default_ledger);

            match topic0 {
                Some("NewCommitmentEvent" | "new_commitment_event" | "new_commitment") => {
                    let commitment = event
                        .topic
                        .as_ref()
                        .and_then(|t| t.get(1))
                        .and_then(normalize_value_to_hex);
                    let index = event
                        .value
                        .as_ref()
                        .and_then(|v| v.get("index"))
                        .and_then(|v| v.as_u64())
                        .and_then(|i| u32::try_from(i).ok());
                    let enc = event
                        .value
                        .as_ref()
                        .and_then(|v| v.get("encrypted_output"))
                        .and_then(value_to_hex_string);

                    if let (Some(c), Some(i), Some(e)) = (commitment, index, enc) {
                        self.pool
                            .process_new_commitment(&c, i, &e, ledger)
                            .map_err(err)?;
                        commitments = commitments.saturating_add(1);
                    }
                }
                Some("NewNullifierEvent" | "new_nullifier_event" | "new_nullifier") => {
                    if let Some(nul) = event
                        .topic
                        .as_ref()
                        .and_then(|t| t.get(1))
                        .and_then(normalize_value_to_hex)
                    {
                        self.pool.process_new_nullifier(&nul, ledger).map_err(err)?;
                        nullifiers = nullifiers.saturating_add(1);
                    }
                }
                _ => {} // skip unknown topics
            }
        }

        Ok(serde_json::json!({
            "commitments": commitments,
            "nullifiers": nullifiers,
        })
        .to_string())
    }

    /// Processes a batch of ASP Membership contract events (JSON array).
    /// Handles `LeafAdded` / `leaf_added` topics.  Events are sorted by
    /// index and already-processed indices are skipped.
    /// Returns the number of new leaves inserted.
    pub fn process_asp_membership_events(
        &mut self,
        events_json: &str,
        default_ledger: u32,
    ) -> Result<u32, JsValue> {
        let events: Vec<StellarEvent> = serde_json::from_str(events_json)
            .map_err(|e| JsValue::from_str(&format!("invalid ASP events JSON: {e}")))?;

        // Collect and sort LeafAdded events by index.
        let mut leaf_events: Vec<(String, u32, String, u32)> = Vec::new();

        for event in &events {
            let topic0 = event
                .topic
                .as_ref()
                .and_then(|t| t.first())
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let is_leaf_added =
                topic0 == "LeafAdded" || topic0 == "leaf_added" || topic0.contains("LeafAdded");

            if !is_leaf_added {
                continue;
            }

            let leaf = event
                .value
                .as_ref()
                .and_then(|v| v.get("leaf"))
                .and_then(normalize_value_to_hex);
            let index = event
                .value
                .as_ref()
                .and_then(|v| v.get("index"))
                .and_then(|v| v.as_u64())
                .and_then(|i| u32::try_from(i).ok());
            let root = event
                .value
                .as_ref()
                .and_then(|v| v.get("root"))
                .and_then(normalize_value_to_hex);
            let ledger = event.ledger.unwrap_or(default_ledger);

            if let (Some(l), Some(i), Some(r)) = (leaf, index, root) {
                leaf_events.push((l, i, r, ledger));
            }
        }

        leaf_events.sort_by_key(|e| e.1);

        // Skip already-processed leaves.
        let next_idx = self.asp.next_index();
        let mut count = 0u32;

        for (leaf, index, root, ledger) in &leaf_events {
            if *index < next_idx {
                continue;
            }
            self.asp
                .process_leaf_added(leaf, *index, root, *ledger)
                .map_err(err)?;
            count = count.saturating_add(1);
        }

        Ok(count)
    }

    // ── ASP Membership ──────────────────────────────────────────────────

    /// Persists a new ASP membership leaf and inserts it into the tree.
    pub fn process_asp_leaf_added(
        &mut self,
        leaf: &str,
        index: u32,
        root: &str,
        ledger: u32,
    ) -> Result<(), JsValue> {
        self.asp
            .process_leaf_added(leaf, index, root, ledger)
            .map_err(err)
    }

    /// Returns the ASP membership Merkle root as LE bytes.
    pub fn get_asp_membership_root(&self) -> Vec<u8> {
        self.asp.root().to_vec()
    }

    /// Returns the ASP membership Merkle root as `0x`-prefixed BE hex.
    pub fn get_asp_membership_root_hex(&self) -> String {
        self.asp.root_hex()
    }

    /// Returns the ASP membership Merkle proof.
    pub fn get_asp_membership_proof(&self, leaf_index: u32) -> Result<WasmMerkleProof, JsValue> {
        let proof = self.asp.get_proof(leaf_index).map_err(err)?;
        Ok(WasmMerkleProof {
            elements: proof.path_elements,
            indices: proof.path_indices,
            root_bytes: proof.root.to_vec(),
        })
    }

    /// Returns the ASP membership leaf record as JSON, or `null`.
    pub fn find_asp_membership_leaf(&self, leaf_hash: &str) -> Result<String, JsValue> {
        let leaf = self.asp.find_leaf_by_hash(leaf_hash).map_err(err)?;
        serde_json::to_string(&leaf).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the number of ASP membership leaves.
    pub fn get_asp_membership_leaf_count(&self) -> Result<u32, JsValue> {
        self.asp.leaf_count().map_err(err)
    }

    /// Returns the next ASP membership leaf insertion index.
    pub fn get_asp_membership_next_index(&self) -> u32 {
        self.asp.next_index()
    }

    /// Rebuilds the ASP membership tree from persisted leaves.
    pub fn rebuild_asp_membership_tree(&mut self) -> Result<u32, JsValue> {
        self.asp.rebuild_tree().map_err(err)
    }

    // ── Notes ───────────────────────────────────────────────────────────

    /// Saves a new note from JSON. Returns the saved note as JSON.
    ///
    /// Expected JSON fields: `commitment`, `owner`, `privateKey`, `blinding`,
    /// `amount`, `leafIndex` (optional), `ledger`, `createdAt`, `isReceived`.
    pub fn save_note(&self, json: &str) -> Result<String, JsValue> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Input {
            commitment: String,
            owner: String,
            private_key: String,
            blinding: String,
            amount: String,
            leaf_index: Option<u32>,
            ledger: u32,
            created_at: String,
            #[serde(default)]
            is_received: bool,
        }
        let inp: Input = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("invalid note JSON: {e}")))?;
        let note = self
            .notes
            .save_note(&NewNote {
                commitment: &inp.commitment,
                owner: &inp.owner,
                private_key: &inp.private_key,
                blinding: &inp.blinding,
                amount: &inp.amount,
                leaf_index: inp.leaf_index,
                ledger: inp.ledger,
                created_at: &inp.created_at,
                is_received: inp.is_received,
            })
            .map_err(err)?;
        serde_json::to_string(&note).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Marks a note as spent. Returns `true` if it existed.
    pub fn mark_note_spent(&self, commitment: &str, ledger: u32) -> Result<bool, JsValue> {
        self.notes.mark_spent(commitment, ledger).map_err(err)
    }

    /// Returns a note by commitment as JSON, or `"null"`.
    pub fn get_note_by_commitment(&self, commitment: &str) -> Result<String, JsValue> {
        let note = self.notes.get_by_commitment(commitment).map_err(err)?;
        serde_json::to_string(&note).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns notes for `owner` as JSON array.
    pub fn get_notes_by_owner(&self, owner: &str) -> Result<String, JsValue> {
        let notes = self.notes.get_by_owner(owner).map_err(err)?;
        serde_json::to_string(&notes).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns unspent notes for `owner` as JSON array.
    pub fn get_unspent_notes(&self, owner: &str) -> Result<String, JsValue> {
        let notes = self.notes.get_unspent(owner).map_err(err)?;
        serde_json::to_string(&notes).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the total balance of unspent notes as a decimal string.
    pub fn get_balance(&self, owner: &str) -> Result<String, JsValue> {
        let balance = self.notes.get_balance(owner).map_err(err)?;
        Ok(balance.to_string())
    }

    /// Returns all notes as JSON array.
    pub fn get_all_notes(&self) -> Result<String, JsValue> {
        let notes = self.notes.get_all().map_err(err)?;
        serde_json::to_string(&notes).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Deletes a note by commitment.
    pub fn delete_note(&self, commitment: &str) -> Result<(), JsValue> {
        self.notes.delete(commitment).map_err(err)
    }

    // ── Public Keys ─────────────────────────────────────────────────────

    /// Stores a public key registration.
    pub fn store_public_key(
        &self,
        address: &str,
        encryption_key: &str,
        note_key: &str,
        ledger: u32,
        registered_at: &str,
    ) -> Result<(), JsValue> {
        self.public_keys
            .store_registration(address, encryption_key, note_key, ledger, registered_at)
            .map_err(err)
    }

    /// Returns the public key entry for `address` as JSON, or `"null"`.
    pub fn get_public_key_by_address(&self, address: &str) -> Result<String, JsValue> {
        let entry = self.public_keys.get_by_address(address).map_err(err)?;
        serde_json::to_string(&entry).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns all public key entries as JSON array.
    pub fn get_all_public_keys(&self) -> Result<String, JsValue> {
        let entries = self.public_keys.get_all().map_err(err)?;
        serde_json::to_string(&entries).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the number of registered public keys.
    pub fn get_public_key_count(&self) -> Result<u32, JsValue> {
        self.public_keys.count().map_err(err)
    }

    // ── Note Scanner ────────────────────────────────────────────────────

    /// Scans encrypted outputs to discover notes for this user.
    /// Returns JSON `{ scanned, found, alreadyKnown }`.
    pub fn scan_for_notes(
        &self,
        enc_priv_key: &[u8],
        note_priv_key: &[u8],
        note_pub_key: &[u8],
        owner: &str,
        created_at: &str,
        from_ledger: Option<u32>,
    ) -> Result<String, JsValue> {
        let enc_key: &[u8; 32] = enc_priv_key
            .try_into()
            .map_err(|_| JsValue::from_str("encryption key must be 32 bytes"))?;
        if note_priv_key.len() != 32 {
            return Err(JsValue::from_str("note private key must be 32 bytes"));
        }
        if note_pub_key.len() != 32 {
            return Err(JsValue::from_str("note public key must be 32 bytes"));
        }

        let keys = ScanKeys {
            encryption_private_key: enc_key,
            note_private_key_le: note_priv_key,
            note_public_key_le: note_pub_key,
        };

        let result = note_scanner::scan_for_notes(
            &self.pool,
            &self.notes,
            &keys,
            owner,
            created_at,
            from_ledger,
        )
        .map_err(err)?;

        Ok(serde_json::json!({
            "scanned": result.scanned,
            "found": result.found,
            "alreadyKnown": result.already_known,
        })
        .to_string())
    }

    /// Checks unspent notes against nullifiers. Returns JSON `{ checked,
    /// markedSpent }`.
    pub fn check_spent_notes(&self, owner: &str) -> Result<String, JsValue> {
        let result =
            note_scanner::check_spent_notes(&self.pool, &self.notes, owner).map_err(err)?;

        Ok(serde_json::json!({
            "checked": result.checked,
            "markedSpent": result.marked_spent,
        })
        .to_string())
    }

    /// Derives the nullifier for a note, returned as `0x`-prefixed BE hex.
    pub fn derive_nullifier(
        &self,
        private_key_le: &[u8],
        commitment_le: &[u8],
        leaf_index: u32,
    ) -> Result<String, JsValue> {
        if private_key_le.len() != 32 || commitment_le.len() != 32 {
            return Err(JsValue::from_str(
                "private key and commitment must be 32 bytes",
            ));
        }
        let nul_le =
            note_scanner::derive_nullifier_for_note(private_key_le, commitment_le, leaf_index)
                .map_err(err)?;
        Ok(utils::field_to_hex(&nul_le))
    }

    // ── Sync Metadata ───────────────────────────────────────────────────

    /// Returns sync metadata for `network` as JSON, or `"null"`.
    pub fn get_sync_metadata(&self, network: &str) -> Result<String, JsValue> {
        let meta = self.db.get_sync_metadata(network).map_err(err)?;
        serde_json::to_string(&meta).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Stores sync metadata (accepts JSON string).
    pub fn put_sync_metadata(&self, json: &str) -> Result<(), JsValue> {
        let meta = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("invalid sync metadata JSON: {e}")))?;
        self.db.put_sync_metadata(&meta).map_err(err)
    }

    /// Deletes sync metadata for `network`.
    pub fn delete_sync_metadata(&self, network: &str) -> Result<(), JsValue> {
        self.db.delete_sync_metadata(network).map_err(err)
    }

    // ── Retention Config ────────────────────────────────────────────────

    /// Returns retention config for `rpc_endpoint` as JSON, or `"null"`.
    pub fn get_retention_config(&self, rpc_endpoint: &str) -> Result<String, JsValue> {
        let config = self.db.get_retention_config(rpc_endpoint).map_err(err)?;
        serde_json::to_string(&config).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Stores retention config (accepts JSON string).
    pub fn put_retention_config(&self, json: &str) -> Result<(), JsValue> {
        let config = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("invalid retention config JSON: {e}")))?;
        self.db.put_retention_config(&config).map_err(err)
    }

    // ── Utilities ───────────────────────────────────────────────────────

    /// Decodes a hex string (with or without `0x`) to bytes.
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
        utils::hex_to_bytes(hex).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Encodes bytes as `0x`-prefixed lowercase hex.
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        utils::bytes_to_hex(bytes)
    }

    /// Converts LE field element bytes to `0x`-prefixed BE hex.
    pub fn field_to_hex(le_bytes: &[u8]) -> String {
        utils::field_to_hex(le_bytes)
    }

    /// Decodes BE hex to LE bytes (for Merkle tree insertion).
    pub fn hex_to_bytes_for_tree(hex: &str) -> Result<Vec<u8>, JsValue> {
        utils::hex_to_bytes_for_tree(hex).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Converts a ledger count to a human-readable duration string.
    pub fn ledgers_to_duration(ledgers: u32) -> String {
        utils::ledgers_to_duration(ledgers)
    }

    // ── Housekeeping ────────────────────────────────────────────────────

    /// Clears all data and resets Merkle trees.
    pub fn clear_all(&mut self) -> Result<(), JsValue> {
        // Delete all rows in one batch, then reset the in-memory trees.
        self.db.clear_all().map_err(err)?;
        self.pool.rebuild_tree().map_err(err)?;
        self.asp.rebuild_tree().map_err(err)?;
        Ok(())
    }

    /// Clears pool data and resets the pool Merkle tree.
    pub fn clear_pool(&mut self) -> Result<(), JsValue> {
        self.pool.clear().map_err(err)
    }

    /// Clears ASP membership data and resets the tree.
    pub fn clear_asp_membership(&mut self) -> Result<(), JsValue> {
        self.asp.clear().map_err(err)
    }

    /// Clears all user notes.
    pub fn clear_notes(&self) -> Result<(), JsValue> {
        self.notes.clear().map_err(err)
    }

    /// Clears all public key registrations.
    pub fn clear_public_keys(&self) -> Result<(), JsValue> {
        self.public_keys.clear().map_err(err)
    }
}
