//! Registration with the public key registry: the inputs built where the keys
//! are stored, and the proofs the registry takes.

use crate::{
    Error,
    state::SqliteStorage,
    storage::map_private_keys,
    types::NotePublicKey,
    zk::{
        encryption::{
            encryption_edwards_key, registration_digest, registration_hash, registration_message,
            sign_encryption_key_ownership,
        },
        flows::KeyOwnershipParams,
    },
};
use serde::{Deserialize, Serialize};

/// Which keys to register, and with which registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRequest {
    pub user_address: String,
    pub kdf_domain: String,
    pub public_key_registry: String,
}

/// Everything a registration needs except the owner's signature and the
/// proof itself, built where the keys are stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationInputs {
    /// Message the owner signs (SEP-53).
    pub message: String,
    pub note_key: NotePublicKey,
    /// Edwards encoding of the X25519 encryption key.
    pub encryption_key: [u8; 32],
    /// The encryption key's signature (64 bytes).
    pub encryption_key_signature: Vec<u8>,
    pub key_ownership: KeyOwnershipParams,
}

/// The registry's `KeyOwnershipProof`.
#[derive(Debug, Clone)]
pub struct RegistrationProof {
    /// Uncompressed `keyOwnership` proof (256 bytes).
    pub note_key_proof: Vec<u8>,
    pub encryption_key_signature: [u8; 64],
    pub owner_signature: [u8; 64],
}

/// Builds the registration inputs from the keys stored for
/// `req.user_address` under `req.kdf_domain`.
pub fn build_registration_inputs(
    storage: &SqliteStorage,
    req: &RegistrationRequest,
) -> Result<RegistrationInputs, Error> {
    let keys = map_private_keys(storage, &req.user_address, &req.kdf_domain)?;
    let note_key = keys.note_keypair.public;
    let encryption_key = encryption_edwards_key(&keys.encryption_keypair.private);
    let message = registration_message(
        &req.public_key_registry,
        &req.user_address,
        &note_key,
        &encryption_key,
    );
    let digest = registration_digest(&message);

    Ok(RegistrationInputs {
        encryption_key_signature: sign_encryption_key_ownership(
            &keys.encryption_keypair.private,
            &digest,
        )
        .to_vec(),
        key_ownership: KeyOwnershipParams {
            note_private_key: keys.note_keypair.private,
            note_public_key: note_key.clone(),
            registration_hash: registration_hash(&digest),
        },
        message,
        note_key,
        encryption_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::KeyDerivationSignature,
        zk::encryption::{derive_encryption_and_note_keypairs, derive_membership_blinding},
    };
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    const OWNER: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
    const REGISTRY: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4";
    const KDF_DOMAIN: &str = "tests";

    fn request() -> RegistrationRequest {
        RegistrationRequest {
            user_address: OWNER.to_string(),
            kdf_domain: KDF_DOMAIN.to_string(),
            public_key_registry: REGISTRY.to_string(),
        }
    }

    #[test]
    fn inputs_are_built_from_the_stored_keys() {
        let mut storage = SqliteStorage::connect_in_memory().expect("storage");
        let signature = KeyDerivationSignature(vec![9; 64]);
        let (note, encryption) =
            derive_encryption_and_note_keypairs(signature.clone()).expect("derive keys");
        let blinding = derive_membership_blinding(&signature, "test").expect("blinding");
        storage
            .save_encryption_and_note_keypairs(OWNER, KDF_DOMAIN, &note, &encryption, &blinding)
            .expect("save keys");

        let inputs = build_registration_inputs(&storage, &request()).expect("inputs");

        assert_eq!(inputs.note_key.0, note.public.0);
        assert_eq!(inputs.key_ownership.note_public_key.0, note.public.0);
        assert_eq!(inputs.key_ownership.note_private_key.0, note.private.0);
        assert_eq!(
            inputs.message,
            registration_message(REGISTRY, OWNER, &note.public, &inputs.encryption_key)
        );
        let digest = registration_digest(&inputs.message);
        assert_eq!(
            inputs.key_ownership.registration_hash,
            registration_hash(&digest)
        );

        let key = VerifyingKey::from_bytes(&inputs.encryption_key).expect("a valid point");
        assert_eq!(key.to_montgomery().to_bytes(), encryption.public.0);
        let challenge: [u8; 32] = Sha256::new()
            .chain_update(b"privacy-pool/registry/encryption-key/v1")
            .chain_update(digest)
            .finalize()
            .into();
        let signature: [u8; 64] = inputs
            .encryption_key_signature
            .as_slice()
            .try_into()
            .expect("64 bytes");
        assert!(
            key.verify_strict(&challenge, &Signature::from_bytes(&signature))
                .is_ok()
        );
    }

    #[test]
    fn inputs_need_stored_keys() {
        let storage = SqliteStorage::connect_in_memory().expect("storage");

        let result = build_registration_inputs(&storage, &request());

        assert!(matches!(result, Err(Error::PrivacyKeysNotFound { .. })));
    }
}
