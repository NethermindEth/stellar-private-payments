-- Which construction produced a stored key row: 1 for the split-free (v1)
-- construction, 2 for the owner-bound (v2) construction. Existing rows
-- default to 1, since the signer-must-equal-owner guard in force before this
-- migration made every stored row owner-bound already - they are known v1,
-- not unknown.
ALTER TABLE keypairs ADD COLUMN binding_version INTEGER NOT NULL DEFAULT 1;
-- The owner address a v2 row was derived for. NULL for v1 rows, which carry
-- no owner of their own.
ALTER TABLE keypairs ADD COLUMN bound_owner TEXT;
