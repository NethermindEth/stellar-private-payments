CREATE TABLE indexing_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Forces only one row
    last_cursor TEXT
);

CREATE TABLE raw_contract_events (
    id TEXT PRIMARY KEY,
    ledger INTEGER NOT NULL,
    contract_id TEXT NOT NULL,
    topics TEXT NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL
);

CREATE TABLE keypairs (
    id INTEGER PRIMARY KEY,
    encryption_private_key BLOB NOT NULL,
    encryption_public_key BLOB NOT NULL,
    note_private_key BLOB NOT NULL,
    note_public_key BLOB NOT NULL,
    account_id INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE TABLE registered_public_keys (
    address TEXT PRIMARY KEY,
    encryption_key BLOB NOT NULL,
    note_key BLOB NOT NULL,
    ledger INTEGER NOT NULL
);

CREATE TABLE pool_leaves (
    leaf_index INTEGER PRIMARY KEY,
    commitment TEXT NOT NULL UNIQUE,
    ledger INTEGER NOT NULL
);

CREATE TABLE pool_nullifiers (
    nullifier TEXT PRIMARY KEY,
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_nullifiers_event_id ON pool_nullifiers(event_id);

CREATE TABLE pool_encrypted_outputs (
    commitment TEXT PRIMARY KEY,
    leaf_index INTEGER NOT NULL,
    encrypted_output TEXT NOT NULL,
    ledger INTEGER NOT NULL
);

CREATE INDEX idx_pool_encrypted_outputs_ledger
    ON pool_encrypted_outputs (ledger);

CREATE TABLE asp_membership_leaves (
    leaf_index INTEGER PRIMARY KEY,
    leaf TEXT NOT NULL,
    root TEXT NOT NULL,
    ledger INTEGER NOT NULL
);

CREATE INDEX idx_asp_membership_leaves_leaf
    ON asp_membership_leaves (leaf);

CREATE TABLE user_notes (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    commitment TEXT NOT NULL,
    private_key TEXT NOT NULL,
    blinding TEXT NOT NULL,
    amount TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_at_ledger INTEGER NOT NULL,
    spent INTEGER NOT NULL DEFAULT 0,
    spent_at_ledger INTEGER,
    is_received INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_user_notes_spent
    ON user_notes (spent);

CREATE INDEX idx_user_notes_owner
    ON user_notes (owner);
