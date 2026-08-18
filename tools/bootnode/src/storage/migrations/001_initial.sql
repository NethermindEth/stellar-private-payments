-- Initial bootnode schema (coexists with legacy tables in shared DBs).
CREATE TABLE bootnode_indexer_state (
  deployment_id TEXT PRIMARY KEY,
  last_cursor TEXT,
  last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
  ledger_tip INTEGER NOT NULL DEFAULT 0,
  in_sync BOOLEAN NOT NULL DEFAULT false,
  last_empty_compress_ledger INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bootnode_get_events_pages (
  id BIGSERIAL PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  cursor_in TEXT,
  start_ledger INTEGER,
  request JSONB NOT NULL,
  result JSONB NOT NULL,
  cursor_out TEXT NOT NULL,
  last_event_ledger INTEGER,
  latest_ledger INTEGER NOT NULL,
  oldest_ledger INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX bootnode_get_events_pages_deployment_cursor_in_uniq
  ON bootnode_get_events_pages(deployment_id, cursor_in) WHERE cursor_in IS NOT NULL;
CREATE UNIQUE INDEX bootnode_get_events_pages_deployment_start_ledger_uniq
  ON bootnode_get_events_pages(deployment_id, start_ledger) WHERE cursor_in IS NULL;
CREATE INDEX bootnode_get_events_pages_latest_ledger_idx
  ON bootnode_get_events_pages(latest_ledger);
CREATE INDEX bootnode_get_events_pages_cursor_out_ledger_idx
  ON bootnode_get_events_pages(deployment_id, cursor_out)
  WHERE last_event_ledger IS NOT NULL;
CREATE INDEX bootnode_get_events_pages_deployment_id_idx
  ON bootnode_get_events_pages(deployment_id);
