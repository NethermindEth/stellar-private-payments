-- Migration 2: one row of derived key material per account.
--
-- Migration 1 left `keypairs` unconstrained and its reader took the newest row
-- (ORDER BY id DESC LIMIT 1), so a second derivation for an account silently
-- shadowed the first and every note encrypted under the earlier keys became
-- invisible. This adds the constraint that makes that impossible, and the
-- application-level check that reports it rather than letting the constraint
-- surface as a bare SQL error.
--
-- Duplicate rows in an existing database fall into two cases, and only one of
-- them is ambiguous:
--
--   * Byte-identical rows. Key derivation is deterministic in the wallet
--     signature, so re-deriving for the same account reproduces exactly the
--     same key material. Collapsing these loses nothing - the surviving row is
--     the same key material the reader was already returning. The DELETE below
--     keeps the lowest id of each identical group.
--
--   * Rows that differ. These are genuinely ambiguous: two different key sets
--     are filed under one account, notes exist under one of them, and nothing
--     in the database records which. Picking one would silently destroy access
--     to the other's notes, so this migration does not pick. CREATE UNIQUE
--     INDEX fails, the database refuses to open, and connect_with_connection
--     turns that into an explanatory error. Loud and recoverable beats quiet
--     and wrong: the rows are still there to be inspected.
--
-- Rows with a NULL account_id are left alone. SQLite treats NULLs as distinct
-- in a unique index so they do not block it, and the reader joins through
-- accounts, so such rows are already unreachable.

DELETE FROM keypairs
WHERE id NOT IN (
    SELECT MIN(id)
    FROM keypairs
    GROUP BY account_id,
             encryption_private_key,
             encryption_public_key,
             note_private_key,
             note_public_key,
             membership_blinding
);

CREATE UNIQUE INDEX idx_keypairs_account_unique ON keypairs(account_id);
