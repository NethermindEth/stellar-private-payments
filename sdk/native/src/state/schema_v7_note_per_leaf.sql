-- Copies of a commitment share its value, in one pool or across pools, so each note is keyed by
-- its `pool_commitments` row.
CREATE TABLE user_notes_new (
    account_id INTEGER NOT NULL,
    commitment_id INTEGER NOT NULL UNIQUE,
    nullifier_id INTEGER UNIQUE,
    expected_nullifier BLOB NOT NULL CHECK (length(expected_nullifier) = 32),
    blinding BLOB NOT NULL CHECK (length(blinding) = 32),
    amount TEXT NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (commitment_id) REFERENCES pool_commitments(id) ON DELETE CASCADE,
    FOREIGN KEY (nullifier_id) REFERENCES pool_nullifiers(id) ON DELETE CASCADE
);
INSERT INTO user_notes_new
    (account_id, commitment_id, nullifier_id, expected_nullifier, blinding, amount)
    SELECT account_id, commitment_id, nullifier_id, expected_nullifier, blinding, amount
    FROM user_notes;

DROP TABLE user_notes;
ALTER TABLE user_notes_new RENAME TO user_notes;
CREATE INDEX idx_user_notes_unspent_expected_nullifier
    ON user_notes(expected_nullifier)
    WHERE nullifier_id IS NULL;

-- The old key kept one note per commitment, so rescan the pools whose copies it dropped.
UPDATE account_commitment_scan SET last_commitment_id = 0 WHERE pool_contract_id IN (
    SELECT r.contract_id
    FROM pool_commitments c
    JOIN raw_contract_events r ON r.id = c.event_id
    WHERE c.commitment IN (
        SELECT commitment FROM pool_commitments GROUP BY commitment HAVING COUNT(*) > 1
    )
);
