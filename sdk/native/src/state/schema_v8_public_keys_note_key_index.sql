-- Reverse address book lookup (note public key -> registering addresses), used
-- to label the owners of GVK-audited notes.
CREATE INDEX IF NOT EXISTS idx_public_keys_note_key ON public_keys (note_key);
