-- A commitment can fill more than one leaf, in one pool or across pools: outputs with the same
-- amount, key, and blinding hash to one value. A nullifier hashes nothing pool-specific, so it can
-- repeat across pools. Each event keeps its own row.
--
-- The copies keep each row's id, which `user_notes` and the scan-state tables refer to.
CREATE TABLE pool_commitments_new (
    id INTEGER PRIMARY KEY,
    commitment BLOB NOT NULL CHECK (length(commitment) = 32),
    leaf_index INTEGER NOT NULL,
    encrypted_output BLOB NOT NULL,
    event_id TEXT NOT NULL UNIQUE,
    gvk_ciphertext TEXT,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
INSERT INTO pool_commitments_new
    (id, commitment, leaf_index, encrypted_output, event_id, gvk_ciphertext)
    SELECT id, commitment, leaf_index, encrypted_output, event_id, gvk_ciphertext
    FROM pool_commitments;

DROP TABLE pool_commitments;
ALTER TABLE pool_commitments_new RENAME TO pool_commitments;
CREATE INDEX idx_pool_commitments_commitment ON pool_commitments (commitment);

CREATE TABLE pool_nullifiers_new (
    id INTEGER PRIMARY KEY,
    nullifier BLOB NOT NULL CHECK (length(nullifier) = 32),
    event_id TEXT NOT NULL UNIQUE,
    gvk_ciphertext TEXT,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
INSERT INTO pool_nullifiers_new (id, nullifier, event_id, gvk_ciphertext)
    SELECT id, nullifier, event_id, gvk_ciphertext
    FROM pool_nullifiers;

DROP TABLE pool_nullifiers;
ALTER TABLE pool_nullifiers_new RENAME TO pool_nullifiers;
CREATE INDEX idx_pool_nullifiers_nullifier ON pool_nullifiers (nullifier);
