-- Keys allowlist leaves by tree and index, so each allowlist has its own leaf 0. SQLite cannot
-- alter a primary key, so rebuild the table, taking each row's tree from its raw event.
CREATE TABLE new_asp_membership_leaves (
    contract_id INTEGER NOT NULL REFERENCES contracts(contract_id),
    leaf_index INTEGER NOT NULL,
    leaf BLOB NOT NULL CHECK (length(leaf) = 32),
    root BLOB NOT NULL CHECK (length(root) = 32),
    event_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY (contract_id, leaf_index),
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
INSERT INTO new_asp_membership_leaves (contract_id, leaf_index, leaf, root, event_id)
SELECT r.contract_id, l.leaf_index, l.leaf, l.root, l.event_id
FROM asp_membership_leaves l
JOIN raw_contract_events r ON r.id = l.event_id;
DROP TABLE asp_membership_leaves;
ALTER TABLE new_asp_membership_leaves RENAME TO asp_membership_leaves;
CREATE INDEX idx_asp_membership_leaves_leaf ON asp_membership_leaves (leaf);

-- Keyed by index alone, the table dropped a leaf whose index another allowlist held, yet the
-- processor marked its event. Clearing the marks replays every event without a row in a
-- derived table: the dropped leaves and the events no table records.
DELETE FROM processed_events;
