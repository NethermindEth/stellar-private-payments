-- Public chain cache. Never add account associations, secrets or private history here.
CREATE TABLE contracts (
    contract_id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE
);

CREATE TABLE indexing_metadata (
    contract_id INTEGER PRIMARY KEY,
    -- RPC pagination cursor (opaque).
    last_cursor TEXT,
    -- Highest ledger reached by the indexer for this contract.
    --
    -- Updated every saved page (max event ledger, or network tip on an empty
    -- page). Used for resume-by-ledger after RPC handoff when cursors are
    -- cleared.
    last_indexed_ledger INTEGER NOT NULL DEFAULT 0,
    -- Latest ledger that the indexer has fully caught up to.
    --
    -- Only advances when the indexer has proven catch-up by fetching an empty
    -- events page for the current cursor. Used for "are we synced?"
    -- preconditions (e.g. proving membership at the current tip).
    last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
);

CREATE TABLE raw_contract_events (
    id TEXT PRIMARY KEY,
    -- Ledger sequence that emitted this event.
    ledger INTEGER NOT NULL,
    contract_id INTEGER NOT NULL,
    topics TEXT NOT NULL,
    value TEXT NOT NULL,
    FOREIGN KEY (contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
);

CREATE TABLE pool_nullifiers (
    id INTEGER PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE CHECK (length(nullifier) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that emitted this nullifier.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

CREATE TABLE pool_commitments (
    id INTEGER PRIMARY KEY,
    commitment BLOB NOT NULL UNIQUE CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that emitted this commitment.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

CREATE TABLE public_keys (
    owner TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    note_key BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that registered these keys.
    event_id  TEXT NOT NULL PRIMARY KEY,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

CREATE TABLE asp_membership_leaves (
    leaf_index INTEGER PRIMARY KEY,
    leaf BLOB NOT NULL CHECK (length(leaf) = 32),
    root BLOB NOT NULL CHECK (length(root) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that added the leaf.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

CREATE INDEX idx_raw_contract_events_ledger_id ON raw_contract_events(ledger, id);

CREATE INDEX IF NOT EXISTS idx_public_keys_owner ON public_keys (owner);

CREATE INDEX idx_asp_membership_leaves_leaf ON asp_membership_leaves (leaf);

ALTER TABLE pool_commitments ADD COLUMN gvk_ciphertext TEXT;

ALTER TABLE pool_nullifiers ADD COLUMN gvk_ciphertext TEXT;

CREATE TABLE app_settings (
    key TEXT PRIMARY KEY CHECK (key IN ('explorer', 'bootnode_config')),
    value JSON NOT NULL
);

CREATE TABLE cache_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
