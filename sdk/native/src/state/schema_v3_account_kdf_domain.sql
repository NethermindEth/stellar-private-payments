-- Accounts are keyed by (address, kdf_domain): each domain derives its own
-- keys, so one Stellar address owns a separate set of notes per domain.
--
-- Keys derived before domains existed can never be used again, so all account
-- data is dropped and owners derive keys again. Foreign keys are off during
-- migrations, so each dependent table is cleared explicitly.
DELETE FROM user_notes;
DELETE FROM account_commitment_scan;
DELETE FROM keypairs;

-- Disclaimer acceptance belongs to the address, not to a domain.
CREATE TABLE disclaimer_acceptances_new (
    address TEXT NOT NULL,
    disclaimer_hash TEXT NOT NULL,
    accepted_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY (address, disclaimer_hash)
);
INSERT INTO disclaimer_acceptances_new (address, disclaimer_hash, accepted_at)
    SELECT a.address, d.disclaimer_hash, d.accepted_at
    FROM disclaimer_acceptances d
    JOIN accounts a ON a.id = d.account_id;

DROP TABLE disclaimer_acceptances;
ALTER TABLE disclaimer_acceptances_new RENAME TO disclaimer_acceptances;
CREATE INDEX idx_disclaimer_acceptances_hash ON disclaimer_acceptances(disclaimer_hash);

DROP TABLE accounts;
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    kdf_domain TEXT NOT NULL,
    UNIQUE (address, kdf_domain)
);

-- One keypair per account.
DROP INDEX idx_keypairs_account_id_id;
CREATE UNIQUE INDEX idx_keypairs_account_id ON keypairs(account_id);
