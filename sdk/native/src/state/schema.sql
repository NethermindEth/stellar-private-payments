-- SQLite schema for local app state.
--
-- Data flow:
-- - Indexer ingestion: `raw_contract_events` stores chain events as fetched from RPC, and
--   `indexing_metadata` stores the RPC pagination cursor.
-- - Event processing: raw events are parsed into derived chain-state tables
--   (`pool_commitments`, `pool_nullifiers`, `public_keys`, `asp_membership_leaves`).
-- - User processing: derived chain state is scanned/decrypted into per-account `user_notes`,
--   with scan progress tracked in the scan-state tables.

-- Contracts known to this local database.
--
-- Storage is event-driven: contracts are inserted on first observation.
CREATE TABLE contracts (
    contract_id INTEGER PRIMARY KEY,
    address TEXT NOT NULL UNIQUE
);

-- Stores the last RPC cursor used by the indexer.
-- Per-contract table keyed by contract_id.
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

-- Append-only log of raw contract events fetched from RPC.
--
-- Notes:
-- - `topics` are stored as a comma-separated list of topic strings.
-- - `value` is the raw event value payload as received from RPC (base64 string).
CREATE TABLE raw_contract_events (
    id TEXT PRIMARY KEY,
    -- Ledger sequence that emitted this event.
    ledger INTEGER NOT NULL,
    contract_id INTEGER NOT NULL,
    topics TEXT NOT NULL,
    value TEXT NOT NULL,
    -- Each raw event's place in its contract's event chain (`chain::EventChain`):
    -- the count and running hash after it, in emission order. NULL until the event
    -- is folded, and for every later event of a contract whose chain an event
    -- could not extend.
    chain_count INTEGER,
    chain_hash BLOB CHECK (chain_hash IS NULL OR length(chain_hash) = 32),
    FOREIGN KEY (contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
);
CREATE INDEX idx_raw_contract_events_ledger_id ON raw_contract_events(ledger, id);
-- One contract's raw events, so the registry sync status finds the registry's
-- unprocessed events without scanning every contract's.
CREATE INDEX idx_raw_contract_events_contract_id ON raw_contract_events (contract_id, id);
CREATE UNIQUE INDEX idx_raw_contract_events_chain ON raw_contract_events(contract_id, chain_count);

-- User accounts known to this local database, keyed by (address, kdf_domain): each domain
-- derives its own keys, so one Stellar address owns a separate set of notes per domain.
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    kdf_domain TEXT NOT NULL,
    UNIQUE (address, kdf_domain)
);

-- Derived key material for an account (one keypair per account).
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
CREATE UNIQUE INDEX idx_keypairs_account_id ON keypairs(account_id);

-- Spent nullifiers observed on-chain for the pool contract.
--
-- Linked to `raw_contract_events` so entries can be traced back to the originating event.
-- A nullifier hashes nothing pool-specific, so it can repeat across pools: each event keeps
-- its own row.
CREATE TABLE pool_nullifiers (
    id INTEGER PRIMARY KEY,
    nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that emitted this nullifier.
    event_id  TEXT NOT NULL UNIQUE,
    -- Admin audit: JSON-serialized GlobalViewKeyCiphertext from pool-gvk events.
    gvk_ciphertext TEXT,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_nullifiers_nullifier ON pool_nullifiers (nullifier);

-- Pool Merkle tree commitments observed on-chain.
--
-- Each commitment carries:
-- - `leaf_index`: index in the pool Merkle tree.
-- - `encrypted_output`: encrypted note output intended for recipients.
--
-- A commitment can fill more than one leaf, in one pool or across pools: outputs with the same
-- amount, key, and blinding hash to one value. Each event keeps its own row.
CREATE TABLE pool_commitments (
    id INTEGER PRIMARY KEY,
    commitment BLOB NOT NULL CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that emitted this commitment.
    event_id  TEXT NOT NULL UNIQUE,
    -- Admin audit: JSON-serialized GlobalViewKeyCiphertext from pool-gvk events.
    gvk_ciphertext TEXT,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_pool_commitments_commitment ON pool_commitments (commitment);

-- An address book of registered public keys emitted by the public key registry contract
--
-- `event_id` ties each registration back to `raw_contract_events` so the registration ledger can
-- be recovered by joining on the raw event.
CREATE TABLE public_keys (
    owner TEXT NOT NULL,
    encryption_key BLOB NOT NULL,
    note_key BLOB NOT NULL,
    -- Foreign key to `raw_contract_events.id` for the event that registered these keys.
    event_id  TEXT NOT NULL PRIMARY KEY,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

CREATE INDEX idx_public_keys_owner ON public_keys (owner);
-- Reverse address book lookup (note public key -> registering addresses), used
-- to label the owners of GVK-audited notes.
CREATE INDEX idx_public_keys_note_key ON public_keys (note_key);

-- Leaves of the ASP membership Merkle tree observed on-chain.
--
-- Used to reconstruct membership proofs locally for proving. Keyed by tree and index, so
-- each allowlist has its own leaf 0.
CREATE TABLE asp_membership_leaves (
    contract_id INTEGER NOT NULL REFERENCES contracts(contract_id),
    leaf_index INTEGER NOT NULL,
    leaf BLOB NOT NULL CHECK (length(leaf) = 32),
    root BLOB NOT NULL CHECK (length(root) = 32),
    -- Foreign key to `raw_contract_events.id` for the event that added the leaf.
    event_id  TEXT NOT NULL UNIQUE,
    PRIMARY KEY (contract_id, leaf_index),
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
CREATE INDEX idx_asp_membership_leaves_leaf ON asp_membership_leaves (leaf);

-- Every raw event the processor has handled, whether or not it left a row in
-- another table. get_unprocessed_events skips the events listed here.
CREATE TABLE processed_events (
    event_id TEXT PRIMARY KEY,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);

-- Notes derived for a specific local account by scanning/decrypting pool commitments.
--
-- `commitment_id` links to a pool commitment (copies of a commitment share its value, so each
-- note is keyed by its `pool_commitments` row). When the corresponding on-chain nullifier is
-- observed, `nullifier_id` is set by reconciliation against `expected_nullifier`.
CREATE TABLE user_notes (
    account_id INTEGER NOT NULL,
    -- FK to `pool_commitments.id` (unique: one derived note per commitment).
    commitment_id INTEGER NOT NULL UNIQUE,
    -- FK to `pool_nullifiers.id` once this note is observed as spent (nullable until spent).
    nullifier_id INTEGER UNIQUE,
    -- Nullifier computed locally from note secrets; matched against on-chain nullifiers.
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount TEXT NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (commitment_id) REFERENCES pool_commitments(id) ON DELETE CASCADE,
    FOREIGN KEY (nullifier_id) REFERENCES pool_nullifiers(id) ON DELETE CASCADE
);
CREATE INDEX idx_user_notes_unspent_expected_nullifier
    ON user_notes(expected_nullifier)
    WHERE nullifier_id IS NULL;

-- Per-account commitment scan high-water mark (pool_commitments.id).
--
-- Tracks how far each account has progressed when scanning commitments for decryptable notes.
CREATE TABLE account_commitment_scan (
    pool_contract_id INTEGER NOT NULL,
    account_id INTEGER NOT NULL,
    last_commitment_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (pool_contract_id, account_id),
    FOREIGN KEY (pool_contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- Per-pool nullifier scan high-water mark (pool_nullifiers.id).
--
-- Tracks how far reconciliation has progressed when matching on-chain nullifiers against
-- `user_notes.expected_nullifier`.
CREATE TABLE nullifier_scan_state (
    pool_contract_id INTEGER PRIMARY KEY,
    last_nullifier_id INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (pool_contract_id) REFERENCES contracts(contract_id) ON DELETE CASCADE
);

-- Terms & Conditions (disclaimer) acceptances per address and disclaimer hash. Acceptance
-- belongs to the address, not to a key derivation domain.
--
-- When the disclaimer text changes, it yields a new hash and each address must accept again.
CREATE TABLE disclaimer_acceptances (
    address TEXT NOT NULL,
    disclaimer_hash TEXT NOT NULL,
    accepted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (address, disclaimer_hash)
);
CREATE INDEX idx_disclaimer_acceptances_hash ON disclaimer_acceptances(disclaimer_hash);

-- Generic application settings store.
--
-- Values are stored as JSON text so UI/runtime settings can evolve without
-- repeated schema changes.
CREATE TABLE app_settings (
    key TEXT PRIMARY KEY,
    value JSON NOT NULL
);

-- High-level log of operations the user performed, scoped per (address, pool).
-- Populated client-side at submit time (deposit / sent / withdraw / advanced)
-- and shown as the pool's operation history. Denormalized by address/pool for
-- simple per-pool queries.
CREATE TABLE app_user_operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    pool_contract_id TEXT NOT NULL,
    op_type TEXT NOT NULL,
    amount TEXT NOT NULL,
    direction TEXT NOT NULL,
    counterparty TEXT,
    tx_hash TEXT,
    -- UTC epoch seconds, generated by the DB at insert time (not the client clock).
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX idx_user_operations_lookup
    ON app_user_operations(address, pool_contract_id, created_at);
