-- Each raw event's place in its contract's event chain (`chain::EventChain`):
-- the count and running hash after it, in emission order. NULL until the event
-- is folded, and for every later event of a contract whose chain an event
-- could not extend.
ALTER TABLE raw_contract_events ADD COLUMN chain_count INTEGER;
ALTER TABLE raw_contract_events ADD COLUMN chain_hash BLOB
    CHECK (chain_hash IS NULL OR length(chain_hash) = 32);
CREATE UNIQUE INDEX idx_raw_contract_events_chain
    ON raw_contract_events(contract_id, chain_count);
