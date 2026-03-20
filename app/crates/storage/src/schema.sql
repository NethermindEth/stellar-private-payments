CREATE TABLE IF NOT EXISTS retention_config (
    rpc_endpoint      TEXT    NOT NULL PRIMARY KEY,
    window            INTEGER NOT NULL,
    description       TEXT    NOT NULL,
    warning_threshold INTEGER NOT NULL,
    detected_at       TEXT    NOT NULL
);

-- JSON blob: shape owned by sync-controller, will change when ported to Rust.
CREATE TABLE IF NOT EXISTS sync_metadata (
    network  TEXT NOT NULL PRIMARY KEY,
    data     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pool_leaves (
    leaf_index  INTEGER NOT NULL PRIMARY KEY,
    commitment  TEXT    NOT NULL UNIQUE,
    ledger      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pool_leaves_commitment ON pool_leaves (commitment);

CREATE TABLE IF NOT EXISTS pool_nullifiers (
    nullifier  TEXT    NOT NULL PRIMARY KEY,
    ledger     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS pool_encrypted_outputs (
    commitment        TEXT    NOT NULL PRIMARY KEY,
    leaf_index        INTEGER NOT NULL,
    encrypted_output  TEXT    NOT NULL,
    ledger            INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pool_outputs_ledger ON pool_encrypted_outputs (ledger);

CREATE TABLE IF NOT EXISTS asp_membership_leaves (
    leaf_index  INTEGER NOT NULL PRIMARY KEY,
    leaf        TEXT    NOT NULL,
    root        TEXT    NOT NULL,
    ledger      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asp_leaves_leaf ON asp_membership_leaves (leaf);

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

CREATE TABLE IF NOT EXISTS registered_public_keys (
    address         TEXT    NOT NULL PRIMARY KEY,
    encryption_key  TEXT    NOT NULL,
    note_key        TEXT    NOT NULL,
    public_key      TEXT    NOT NULL,
    ledger          INTEGER NOT NULL,
    registered_at   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_public_keys_ledger ON registered_public_keys (ledger);
