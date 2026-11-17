-- The encryption public key changed format: it is now 1216 bytes (see
-- `EncryptionPublicKey::LEN`), where it was 32.
--
-- Rows holding the old keys cannot be read any more. Keypairs are re-derived
-- from the wallet signature (under the new key derivation domain) and
-- registrations are re-indexed from their events, so both are dropped.
DELETE FROM keypairs WHERE length(encryption_public_key) != 1216;
DELETE FROM public_keys WHERE length(encryption_key) != 1216;
