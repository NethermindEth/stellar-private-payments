-- Bootnode event archive (coexists with legacy tables in shared DBs).
CREATE TABLE bootnode_indexer_state (
  deployment_id TEXT PRIMARY KEY,
  last_upstream_cursor TEXT,
  ledger_tip INTEGER NOT NULL DEFAULT 0,
  oldest_ledger INTEGER NOT NULL DEFAULT 0,
  archive_ready BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bootnode_events (
  deployment_id TEXT NOT NULL,
  id TEXT NOT NULL,
  ledger INTEGER NOT NULL,
  payload JSONB NOT NULL,
  PRIMARY KEY (deployment_id, id)
);

CREATE INDEX bootnode_events_deployment_ledger_id_idx
  ON bootnode_events (deployment_id, ledger, id);
