-- Events that parse but leave no row in a saved-event table. Without this,
-- get_unprocessed_events re-reads them on every pass forever.
CREATE TABLE processed_events (event_id TEXT PRIMARY KEY);
