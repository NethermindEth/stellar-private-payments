-- Unified storage schema for the shielded pool.
-- Column names mirror the JavaScript field names (snake_case equivalents)
-- so diffs against the JS state modules are readable line-by-line.

-- Mirrors IndexedDB store: retention_config  (keyPath: 'rpcEndpoint')
CREATE TABLE IF NOT EXISTS retention_config (
    rpc_endpoint      TEXT    NOT NULL PRIMARY KEY,
    window            INTEGER NOT NULL,
    description       TEXT    NOT NULL,
    warning_threshold INTEGER NOT NULL,
    detected_at       TEXT    NOT NULL
);

-- Mirrors IndexedDB store: sync_metadata  (keyPath: 'network')
-- Stored as a JSON blob because the shape (poolSync, aspMembershipSync cursors)
-- is owned by sync-controller and will change when that module is ported to Rust.
CREATE TABLE IF NOT EXISTS sync_metadata (
    network  TEXT NOT NULL PRIMARY KEY,
    data     TEXT NOT NULL
);

-- Mirrors IndexedDB store: pool_leaves  (keyPath: 'index', unique index on 'commitment')
CREATE TABLE IF NOT EXISTS pool_leaves (
    leaf_index  INTEGER NOT NULL PRIMARY KEY,
    commitment  TEXT    NOT NULL UNIQUE,
    ledger      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pool_leaves_commitment ON pool_leaves (commitment);

-- Mirrors IndexedDB store: pool_nullifiers  (keyPath: 'nullifier')
CREATE TABLE IF NOT EXISTS pool_nullifiers (
    nullifier  TEXT    NOT NULL PRIMARY KEY,
    ledger     INTEGER NOT NULL
);

-- Mirrors IndexedDB store: pool_encrypted_outputs  (keyPath: 'commitment', index on 'ledger')
-- JS field names: commitment, index, encryptedOutput, ledger
CREATE TABLE IF NOT EXISTS pool_encrypted_outputs (
    commitment        TEXT    NOT NULL PRIMARY KEY,
    leaf_index        INTEGER NOT NULL,
    encrypted_output  TEXT    NOT NULL,
    ledger            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pool_outputs_ledger ON pool_encrypted_outputs (ledger);

-- Mirrors IndexedDB store: asp_membership_leaves  (keyPath: 'index', non-unique index on 'leaf')
-- Includes 'root' field written by asp-membership-store for contract root verification.
CREATE TABLE IF NOT EXISTS asp_membership_leaves (
    leaf_index  INTEGER NOT NULL PRIMARY KEY,
    leaf        TEXT    NOT NULL,
    root        TEXT    NOT NULL,
    ledger      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asp_leaves_leaf ON asp_membership_leaves (leaf);

-- Mirrors IndexedDB store: user_notes  (keyPath: 'id', indexes on 'spent' and 'owner')
-- JS field names: id, owner, privateKey, blinding, amount, leafIndex,
--                 createdAt, createdAtLedger, spent, spentAtLedger, isReceived
CREATE TABLE IF NOT EXISTS user_notes (
    id                TEXT    NOT NULL PRIMARY KEY,
    owner             TEXT    NOT NULL,
    private_key       TEXT    NOT NULL,
    blinding          TEXT    NOT NULL,
    amount            TEXT    NOT NULL,
    leaf_index        INTEGER,
    created_at        TEXT    NOT NULL,
    created_at_ledger INTEGER NOT NULL,
    spent             INTEGER NOT NULL DEFAULT 0,
    spent_at_ledger   INTEGER,
    is_received       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_user_notes_owner ON user_notes (owner);
CREATE INDEX IF NOT EXISTS idx_user_notes_spent ON user_notes (spent);

-- Mirrors IndexedDB store: registered_public_keys  (keyPath: 'address', index on 'ledger')
-- JS field names: address, encryptionKey, noteKey, publicKey (legacy alias), ledger, registeredAt
CREATE TABLE IF NOT EXISTS registered_public_keys (
    address         TEXT    NOT NULL PRIMARY KEY,
    encryption_key  TEXT    NOT NULL,
    note_key        TEXT    NOT NULL,
    public_key      TEXT    NOT NULL,
    ledger          INTEGER NOT NULL,
    registered_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_public_keys_ledger ON registered_public_keys (ledger);
