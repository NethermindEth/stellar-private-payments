-- Added allowlists whose events the archive holds from their deployment ledger.
ALTER TABLE bootnode_state ADD COLUMN archived_allowlists TEXT[] NOT NULL DEFAULT '{}';
