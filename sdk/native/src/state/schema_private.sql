-- Private vault format, version 1. Chain tables live in the public database.
PRAGMA application_id = 0x53505056; -- SPPV, committed with the initial schema.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE
);
CREATE TABLE keypairs (
    id INTEGER PRIMARY KEY,
    encryption_private_key BLOB NOT NULL,
    encryption_public_key BLOB NOT NULL,
    note_private_key BLOB NOT NULL,
    note_public_key BLOB NOT NULL,
    membership_blinding BLOB NOT NULL,
    account_id INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX idx_keypairs_account_id_id ON keypairs(account_id, id);

CREATE TABLE user_notes (
    id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 32),
    account_id INTEGER NOT NULL,
    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)),
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX idx_user_notes_unspent_expected_nullifier ON user_notes(expected_nullifier) WHERE spent = 0;
CREATE TABLE account_commitment_scan (
    pool_contract_id TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    last_leaf_index INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (pool_contract_id, account_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE TABLE disclaimer_acceptances (
    account_id INTEGER NOT NULL,
    disclaimer_hash TEXT NOT NULL,
    accepted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (account_id, disclaimer_hash),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
CREATE INDEX idx_disclaimer_acceptances_hash ON disclaimer_acceptances(disclaimer_hash);
CREATE TABLE private_settings (
    key TEXT PRIMARY KEY,
    value JSON NOT NULL
);
CREATE TABLE app_user_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    pool_contract_id TEXT NOT NULL,
    op_type TEXT NOT NULL,
    amount TEXT NOT NULL,
    direction TEXT NOT NULL,
    counterparty TEXT,
    tx_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX idx_user_operations_lookup ON app_user_operations(address, pool_contract_id, created_at);
