-- Private notes reference stable commitment hashes, not public-cache row IDs.
CREATE INDEX idx_pool_commitments_leaf_index ON pool_commitments(leaf_index);
CREATE TABLE user_notes_v3 (
    id BLOB NOT NULL PRIMARY KEY CHECK (length(id) = 32),
    account_id INTEGER NOT NULL,
    spent INTEGER NOT NULL DEFAULT 0 CHECK (spent IN (0, 1)),
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
INSERT INTO user_notes_v3
    SELECT c.commitment, n.account_id, n.nullifier_id IS NOT NULL,
           n.expected_nullifier, n.blinding, n.amount
    FROM user_notes n JOIN pool_commitments c ON c.id = n.commitment_id;
CREATE TEMP TABLE private_reference_check(valid INTEGER CHECK (valid = 1));
INSERT INTO private_reference_check SELECT (SELECT count(*) FROM user_notes_v3) = (SELECT count(*) FROM user_notes);
DROP TABLE private_reference_check;
DROP TABLE user_notes;
ALTER TABLE user_notes_v3 RENAME TO user_notes;
CREATE INDEX idx_user_notes_unspent_expected_nullifier ON user_notes(expected_nullifier) WHERE spent = 0;

-- Addresses and leaf indexes survive public-cache reconstruction. Reset old
-- scan cursors once; existing notes are retained and inserts are idempotent.
DROP TABLE account_commitment_scan;
CREATE TABLE account_commitment_scan (
    pool_contract_id TEXT NOT NULL,
    account_id INTEGER NOT NULL,
    last_leaf_index INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (pool_contract_id, account_id),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
DROP TABLE nullifier_scan_state;
