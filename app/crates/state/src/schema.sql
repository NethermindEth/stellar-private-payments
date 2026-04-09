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
    nullifier BLOB NOT NULL PRIMARY KEY CHECK (length(nullifier) = 32),
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_nullifiers_event_id ON pool_nullifiers(event_id);

CREATE TABLE pool_commitments (
    commitment BLOB NOT NULL PRIMARY KEY CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_commitments_event_id ON pool_commitments(event_id);

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
    owner TEXT NOT NULL,
    commitment BLOB NOT NULL CHECK (length(commitment) = 32),
    private_key BLOB NOT NULL CHECK (length(private_key) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount INTEGER NOT NULL,
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
