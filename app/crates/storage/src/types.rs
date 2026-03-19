use serde::{Deserialize, Serialize};

/// `pool_leaves` — `pool-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolLeaf {
    /// Leaf index (primary key).
    pub index: u32,
    /// Commitment hash (hex).
    pub commitment: String,
    /// Ledger when added.
    pub ledger: u32,
}

/// `pool_nullifiers` — `pool-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolNullifier {
    /// Nullifier hash (hex, primary key).
    pub nullifier: String,
    /// Ledger when spent.
    pub ledger: u32,
}

/// `pool_encrypted_outputs` — `pool-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolEncryptedOutput {
    /// Commitment hash (hex, primary key).
    pub commitment: String,
    /// Leaf index in the pool tree.
    #[serde(rename = "index")]
    pub leaf_index: u32,
    /// Encrypted note bytes (hex).
    #[serde(rename = "encryptedOutput")]
    pub encrypted_output: String,
    /// Ledger when created.
    pub ledger: u32,
}

/// `asp_membership_leaves` — `asp-membership-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AspMembershipLeaf {
    /// Leaf index (primary key).
    pub index: u32,
    /// Leaf hash (hex).
    pub leaf: String,
    /// Tree root after insertion.
    pub root: String,
    /// Ledger when added.
    pub ledger: u32,
}

/// `user_notes` — `notes-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserNote {
    /// Commitment hash (hex, primary key).
    pub id: String,
    /// Owner Stellar address.
    pub owner: String,
    /// Note private key (hex).
    pub private_key: String,
    /// Blinding factor (hex).
    pub blinding: String,
    /// Amount as decimal string.
    pub amount: String,
    /// Leaf index; `None` until mined.
    pub leaf_index: Option<u32>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Ledger when created.
    pub created_at_ledger: u32,
    /// Whether the note has been spent.
    pub spent: bool,
    /// Ledger when spent; `None` if unspent.
    pub spent_at_ledger: Option<u32>,
    /// `true` if received via transfer, not created locally.
    pub is_received: bool,
}

/// `registered_public_keys` — `public-key-store.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyEntry {
    /// Stellar address (primary key).
    pub address: String,
    /// X25519 encryption public key (hex).
    pub encryption_key: String,
    /// BN254 note public key (hex).
    pub note_key: String,
    /// Legacy alias for `encryption_key`.
    pub public_key: String,
    /// Ledger when registered on-chain.
    pub ledger: u32,
    /// ISO-8601 timestamp when stored locally.
    pub registered_at: String,
}

/// `retention_config` — `retention-verifier.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionConfig {
    /// RPC endpoint URL (primary key).
    pub rpc_endpoint: String,
    /// Retention window in ledgers (17280 ≈ 24 h, 120960 ≈ 7 d).
    pub window: u32,
    /// Human-readable description.
    pub description: String,
    /// Warning threshold in ledgers (80% of `window`).
    pub warning_threshold: u32,
    /// ISO-8601 timestamp when detected.
    pub detected_at: String,
}

/// Inner sync cursor — `sync-controller.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCursor {
    /// Last synced ledger.
    pub last_ledger: u32,
    /// Stellar RPC pagination cursor.
    pub last_cursor: Option<String>,
    /// `true` when gap exceeds retention window.
    pub sync_broken: bool,
}

/// `sync_metadata` — `sync-controller.js`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncMetadata {
    /// Network name (primary key).
    pub network: String,
    /// Pool contract sync cursor.
    pub pool_sync: SyncCursor,
    /// ASP Membership contract sync cursor.
    pub asp_membership_sync: SyncCursor,
    /// ISO-8601 timestamp of last successful sync.
    pub last_successful_sync: Option<String>,
}
