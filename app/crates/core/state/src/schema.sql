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

CREATE TABLE pool_nullifiers (
    id INTEGER PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE CHECK (length(nullifier) = 32),
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_nullifiers_event_id ON pool_nullifiers(event_id);

CREATE TABLE pool_commitments (
    id INTEGER PRIMARY KEY,
    commitment BLOB NOT NULL UNIQUE CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_commitments_event_id ON pool_commitments(event_id);

-- An address book of registered public keys in the pool contract for sending private transfers
CREATE TABLE public_keys (
    owner TEXT PRIMARY KEY,
    encryption_key BLOB NOT NULL,
    note_key BLOB NOT NULL,
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_public_keys_event_id ON public_keys(event_id);

CREATE TABLE asp_membership_leaves (
    leaf_index INTEGER PRIMARY KEY,
    leaf BLOB NOT NULL CHECK (length(leaf) = 32),
    root BLOB NOT NULL CHECK (length(root) = 32),
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_asp_membership_leaves_event_id ON asp_membership_leaves(event_id);
CREATE INDEX idx_asp_membership_leaves_leaf ON asp_membership_leaves (leaf);

CREATE TABLE user_notes (
    id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 32),
    account_id INTEGER NOT NULL,
    commitment_id INTEGER NOT NULL UNIQUE,
    nullifier_id INTEGER UNIQUE,
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount INTEGER NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (commitment_id) REFERENCES pool_commitments(id) ON DELETE CASCADE,
    FOREIGN KEY (nullifier_id) REFERENCES pool_nullifiers(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_notes_expected_nullifier ON user_notes (expected_nullifier);

-- Per-account commitment scan high-water mark (pool_commitments.id).
CREATE TABLE account_commitment_scan (
    account_id INTEGER PRIMARY KEY,
    last_commitment_id INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Global nullifier scan high-water mark (pool_nullifiers.id).
CREATE TABLE nullifier_scan_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_nullifier_id INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO nullifier_scan_state (id, last_nullifier_id) VALUES (1, 0);

-- Round-robin scheduler for commitment scanning fairness across accounts.
CREATE TABLE notes_scan_scheduler (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    next_account_offset INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO notes_scan_scheduler (id, next_account_offset) VALUES (1, 0);
