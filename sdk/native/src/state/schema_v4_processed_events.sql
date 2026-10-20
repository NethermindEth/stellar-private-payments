-- Every raw event the processor has handled, whether or not it left a row in
-- another table. get_unprocessed_events skips the events listed here.
CREATE TABLE processed_events (
    event_id TEXT PRIMARY KEY,
    FOREIGN KEY (event_id) REFERENCES raw_contract_events(id) ON DELETE CASCADE
);
