-- Reverse address book lookup (note public key -> registering addresses), used
-- to label the owners of GVK-audited notes.
CREATE INDEX IF NOT EXISTS idx_public_keys_note_key ON public_keys (note_key);

-- One contract's raw events, so the registry sync status finds the registry's
-- unprocessed events without scanning every contract's.
CREATE INDEX IF NOT EXISTS idx_raw_contract_events_contract_id ON raw_contract_events (contract_id, id);
