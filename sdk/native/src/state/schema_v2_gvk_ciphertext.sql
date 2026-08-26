-- Admin audit: JSON-serialized GlobalViewKeyCiphertext from pool-gvk events.
ALTER TABLE pool_commitments ADD COLUMN gvk_ciphertext TEXT;
ALTER TABLE pool_nullifiers ADD COLUMN gvk_ciphertext TEXT;
