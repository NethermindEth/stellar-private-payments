-- SQLite schema for local app state.
--
-- Data flow:
-- - Indexer ingestion: `raw_contract_events` stores chain events as fetched from RPC, and
--   `indexing_metadata` stores the RPC pagination cursor.
-- - Event processing: raw events are parsed into derived chain-state tables
--   (`pool_commitments`, `pool_nullifiers`, `public_keys`, `asp_membership_leaves`).
-- - User processing: derived chain state is scanned/decrypted into per-account `user_notes`,
--   with scan progress tracked in the scan-state tables.

-- Stores the last RPC cursor used by the indexer.
-- Singleton table enforced by `id CHECK (id = 1)`.
CREATE TABLE indexing_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- Forces only one row
    -- RPC pagination cursor (opaque).
    last_cursor TEXT
);

-- Append-only log of raw contract events fetched from RPC.
--
-- Notes:
-- - `topics` are stored as a comma-separated list of topic strings.
-- - `value` is the raw event value payload as received from RPC (base64 string).
CREATE TABLE raw_contract_events (
    id TEXT PRIMARY KEY,
    -- Ledger sequence that emitted this event.
    ledger INTEGER NOT NULL,
    contract_id TEXT NOT NULL,
    topics TEXT NOT NULL,
    value TEXT NOT NULL
);

-- User accounts known to this local database (one per Stellar address).
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL
);

-- Derived key material for an account.
--
-- There may be multiple rows per account (e.g. re-derivation); the application typically uses
-- the latest row (max(id)) per account.
CREATE TABLE keypairs (
    id INTEGER PRIMARY KEY,
    encryption_private_key BLOB NOT NULL,
    encryption_public_key BLOB NOT NULL,
    note_private_key BLOB NOT NULL,
    note_public_key BLOB NOT NULL,
    account_id INTEGER,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Spent nullifiers observed on-chain for the pool contract.
--
-- Linked to `raw_contract_events` so entries can be traced back to the originating event.
CREATE TABLE pool_nullifiers (
    id INTEGER PRIMARY KEY,
    nullifier BLOB NOT NULL UNIQUE CHECK (length(nullifier) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that emitted this nullifier.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_nullifiers_event_id ON pool_nullifiers(event_id);

-- Pool Merkle tree commitments observed on-chain.
--
-- Each commitment carries:
-- - `leaf_index`: index in the pool Merkle tree.
-- - `encrypted_output`: encrypted note output intended for recipients.
CREATE TABLE pool_commitments (
    id INTEGER PRIMARY KEY,
    commitment BLOB NOT NULL UNIQUE CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that emitted this commitment.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_commitments_event_id ON pool_commitments(event_id);

-- An address book of registered public keys in the pool contract for sending private transfers
--
-- `event_id` ties each registration back to `raw_contract_events` so the registration ledger can
-- be recovered by joining on the raw event.
CREATE TABLE public_keys (
    owner TEXT PRIMARY KEY,
    encryption_key BLOB NOT NULL,
    note_key BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that registered these keys.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_public_keys_event_id ON public_keys(event_id);

-- Leaves of the ASP membership Merkle tree observed on-chain.
--
-- Used to reconstruct membership proofs locally for proving.
CREATE TABLE asp_membership_leaves (
    leaf_index INTEGER PRIMARY KEY,
    leaf BLOB NOT NULL CHECK (length(leaf) = 32),
    root BLOB NOT NULL CHECK (length(root) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that added the leaf.
    event_id  TEXT NOT NULL UNIQUE,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_asp_membership_leaves_event_id ON asp_membership_leaves(event_id);
CREATE INDEX idx_asp_membership_leaves_leaf ON asp_membership_leaves (leaf);

-- Notes derived for a specific local account by scanning/decrypting pool commitments.
--
-- `commitment_id` links to a pool commitment. When the corresponding on-chain nullifier is
-- observed, `nullifier_id` is set by reconciliation against `expected_nullifier`.
CREATE TABLE user_notes (
    id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 32),
    account_id INTEGER NOT NULL,
    -- FK to `pool_commitments.id` (unique: one derived note per commitment).
    commitment_id INTEGER NOT NULL UNIQUE,
    -- FK to `pool_nullifiers.id` once this note is observed as spent (nullable until spent).
    nullifier_id INTEGER UNIQUE,
    -- Nullifier computed locally from note secrets; matched against on-chain nullifiers.
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount INTEGER NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (commitment_id) REFERENCES pool_commitments(id) ON DELETE CASCADE,
    FOREIGN KEY (nullifier_id) REFERENCES pool_nullifiers(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_notes_expected_nullifier ON user_notes (expected_nullifier);

-- Per-account commitment scan high-water mark (pool_commitments.id).
--
-- Tracks how far each account has progressed when scanning commitments for decryptable notes.
CREATE TABLE account_commitment_scan (
    account_id INTEGER PRIMARY KEY,
    last_commitment_id INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Global nullifier scan high-water mark (pool_nullifiers.id).
--
-- Tracks how far reconciliation has progressed when matching on-chain nullifiers against
-- `user_notes.expected_nullifier`.
CREATE TABLE nullifier_scan_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_nullifier_id INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO nullifier_scan_state (id, last_nullifier_id) VALUES (1, 0);

-- Round-robin scheduler for commitment scanning fairness across accounts.
--
-- Maintains which account should be scanned first on the next scan pass.
CREATE TABLE notes_scan_scheduler (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    next_account_offset INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO notes_scan_scheduler (id, next_account_offset) VALUES (1, 0);
