#![no_std]

use contract_types::Groth16Proof;
use pool_core::CircomGroth16VerifierClient;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, String, U256, address_payload::AddressPayload, contract,
    contracterror, contractevent, contractimpl, contracttype, crypto::bn254::Bn254Fr, vec,
};
use soroban_utils::{EventChain, constants::bn256_modulus, event_chain, publish_event};

/// User account registration data
///
/// Used for registering a user's public key to enable encrypted communication
/// for receiving transfers.
/// Not required to interact with the pool. But facilitates in-pool transfers
/// via events. As parties can learn about each other public key.
#[contracttype]
pub struct Account {
    /// Owner address of the account
    pub owner: Address,
    /// Public key notes are encrypted to, [`ENCRYPTION_KEY_LEN`] bytes
    pub encryption_key: Bytes,
    /// BN254 note public key for creating commitments (32 bytes)
    pub note_key: Bytes,
}

/// Proof that the registrant holds the owner's master key and the private key
/// of the note key.
///
/// Both are made over the registration digest `D`. The encryption key is
/// covered by the owner's signature but has no proof of its own.
#[contracttype]
#[derive(Clone)]
pub struct KeyOwnershipProof {
    /// `keyOwnership` proof with public inputs `[note_key, D mod r]`
    pub note_key_proof: Groth16Proof,
    /// Ed25519 signature by the owner's master key over `D` (SEP-53)
    pub owner_signature: BytesN<64>,
}

/// Event emitted when a user registers their public keys
///
/// This event allows other users to discover keys for sending private
/// transfers. Two key types are required:
/// - encryption_key: key for encrypting note data (amount, blinding)
/// - note_key: BN254 key for creating commitments in the ZK circuit
#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    /// Address of the account owner
    #[topic]
    pub owner: Address,
    /// Public key notes are encrypted to
    pub encryption_key: Bytes,
    /// BN254 note public key
    pub note_key: Bytes,
    /// SEP-53 signature by the owner's master key over the registration
    /// message, so clients can verify the event without trusting its source.
    pub owner_signature: BytesN<64>,
}

/// Contract error types for the public key registry
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The note key is not 32 bytes, or the encryption key is not
    /// [`ENCRYPTION_KEY_LEN`] bytes
    InvalidKeyLength = 1,
    /// The owner is a contract address, which has no master key
    OwnerNotAccount = 2,
    /// The note key is not a canonical BN254 scalar field element
    NonCanonicalNoteKey = 3,
    /// The owner already registered different keys
    AlreadyRegistered = 5,
    /// The verifier refused the note key ownership proof
    InvalidProof = 6,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum DataKey {
    Registration(Address),
    /// Privacy key derivation domain. Immutable.
    KdfDomain,
    /// Groth16 verifier for the `keyOwnership` circuit. Immutable.
    Verifier,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct Registration {
    /// `sha256(note_key || encryption_key)`. The keys themselves are not
    /// stored, as nothing on chain reads them: clients get them from the
    /// [`PublicKeyEvent`]. The hash is enough to tell a repeated registration
    /// from a conflicting one. Both keys have a fixed length, so the
    /// concatenation is unambiguous.
    keys_hash: BytesN<32>,
}

/// Required length of the encryption key, which the SDK defines as
/// `EncryptionPublicKey::LEN`. The registry checks only the length, it does not
/// interpret the key.
pub const ENCRYPTION_KEY_LEN: u32 = 1216;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

const SEP53_PREFIX: &[u8] = b"Stellar Signed Message:\n";

/// Text the owner signs to register `account` with the registry at `registry`:
///
/// ```text
/// Privacy Pool Key Registration [v1]
/// Registry: <registry strkey>
/// Account: <owner strkey>
/// Note key: 0x<hex of the 32 note_key bytes>
/// Encryption key: 0x<hex of the encryption_key bytes>
/// ```
pub fn registration_message(env: &Env, registry: &Address, account: &Account) -> Bytes {
    let mut message = Bytes::from_slice(env, b"Privacy Pool Key Registration [v1]\nRegistry: ");
    message.append(&registry.to_string().to_bytes());
    message.extend_from_slice(b"\nAccount: ");
    message.append(&account.owner.to_string().to_bytes());
    message.extend_from_slice(b"\nNote key: ");
    append_hex(&mut message, &account.note_key);
    message.extend_from_slice(b"\nEncryption key: ");
    append_hex(&mut message, &account.encryption_key);
    message
}

/// SEP-53 digest: `sha256("Stellar Signed Message:\n" || message)`.
pub fn registration_digest(env: &Env, message: &Bytes) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, SEP53_PREFIX);
    payload.append(message);
    env.crypto().sha256(&payload).to_bytes()
}

/// Appends `0x` and the lowercase hex of a key, encoded locally in 32-byte
/// chunks so the host copies each key once.
fn append_hex(out: &mut Bytes, key: &Bytes) {
    out.extend_from_slice(b"0x");
    let len = key.len();
    let mut offset = 0u32;
    while offset < len {
        let end = offset.saturating_add(32).min(len);
        let n = end.saturating_sub(offset) as usize;
        let mut raw = [0u8; 32];
        key.slice(offset..end).copy_into_slice(&mut raw[..n]);
        let mut hex = [0u8; 64];
        for (pair, byte) in hex.chunks_exact_mut(2).zip(&raw[..n]) {
            pair[0] = HEX_DIGITS[usize::from(byte >> 4)];
            pair[1] = HEX_DIGITS[usize::from(byte & 0x0f)];
        }
        out.extend_from_slice(&hex[..n.saturating_mul(2)]);
        offset = end;
    }
}

/// Reads a little-endian 32-byte value as a big-endian `U256`.
fn le_bytes_to_u256(env: &Env, bytes: &BytesN<32>) -> U256 {
    let mut be = bytes.to_array();
    be.reverse();
    U256::from_be_bytes(env, &Bytes::from_array(env, &be))
}

/// Public key registry contract.
///
/// Emits one global registration event stream for user key discovery across
/// all pools in a deployment.
#[contract]
pub struct PublicKeyRegistry;

#[contractimpl]
impl PublicKeyRegistry {
    pub fn __constructor(env: Env, kdf_domain: String, verifier: Address) {
        let instance = env.storage().instance();
        instance.set(&DataKey::KdfDomain, &kdf_domain);
        instance.set(&DataKey::Verifier, &verifier);
    }

    /// Get the deployment's privacy key derivation domain.
    pub fn get_kdf_domain(env: Env) -> String {
        env.storage()
            .instance()
            .get(&DataKey::KdfDomain)
            .expect("constructor sets the kdf domain")
    }

    /// Get the `keyOwnership` verifier.
    pub fn get_verifier(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Verifier)
            .expect("constructor sets the verifier")
    }

    /// Returns the running hash over every event the registry has published,
    /// and how many there were, for clients to check the events they synced.
    pub fn event_chain(env: Env) -> EventChain {
        event_chain::event_chain(&env)
    }

    /// Register a user's public encryption and note keys.
    ///
    /// Registration is write-once: registering the same keys again changes
    /// nothing, and different keys are refused. `proof` must show that the
    /// registrant holds the owner's master key and the note private key.
    ///
    /// Renews the registry by at most a day.
    pub fn register(env: Env, account: Account, proof: KeyOwnershipProof) -> Result<(), Error> {
        account.owner.require_auth();
        soroban_utils::extend_instance(&env);

        let note_key =
            BytesN::<32>::try_from(&account.note_key).map_err(|_| Error::InvalidKeyLength)?;
        if account.encryption_key.len() != ENCRYPTION_KEY_LEN {
            return Err(Error::InvalidKeyLength);
        }
        let Some(AddressPayload::AccountIdPublicKeyEd25519(owner_key)) = account.owner.to_payload()
        else {
            return Err(Error::OwnerNotAccount);
        };

        // One single canonical encoding per note key to prevent re-writes
        let note_key_value = le_bytes_to_u256(&env, &note_key);
        if note_key_value >= bn256_modulus(&env) {
            return Err(Error::NonCanonicalNoteKey);
        }

        let key = DataKey::Registration(account.owner.clone());
        let mut keys = account.note_key.clone();
        keys.append(&account.encryption_key);
        let next = Registration {
            keys_hash: env.crypto().sha256(&keys).to_bytes(),
        };
        if let Some(existing) = env
            .storage()
            .persistent()
            .get::<DataKey, Registration>(&key)
        {
            return if existing == next {
                // A no-op re-registration still renews the registration entry,
                // so a user can keep their published keys alive.
                soroban_utils::extend_persistent(&env, &key);
                Ok(())
            } else {
                Err(Error::AlreadyRegistered)
            };
        }

        let message = registration_message(&env, &env.current_contract_address(), &account);
        let digest = registration_digest(&env, &message);
        env.crypto()
            .ed25519_verify(&owner_key, &digest.clone().into(), &proof.owner_signature);

        Self::verify_note_key_proof(
            &env,
            &proof.note_key_proof,
            Bn254Fr::from_u256(note_key_value),
            Bn254Fr::from_bytes(digest),
        )?;

        env.storage().persistent().set(&key, &next);
        soroban_utils::extend_persistent(&env, &key);
        publish_event!(
            &env,
            PublicKeyEvent {
                owner: account.owner,
                encryption_key: account.encryption_key,
                note_key: account.note_key,
                owner_signature: proof.owner_signature.clone(),
            }
        );
        Ok(())
    }

    fn verify_note_key_proof(
        env: &Env,
        proof: &Groth16Proof,
        note_key: Bn254Fr,
        registration_hash: Bn254Fr,
    ) -> Result<(), Error> {
        let verifier = Self::get_verifier(env.clone());
        soroban_utils::extend_contract(env, &verifier);
        let public_inputs = vec![env, note_key, registration_hash];

        match CircomGroth16VerifierClient::new(env, &verifier).try_verify(proof, &public_inputs) {
            Ok(Ok(true)) => Ok(()),
            _ => Err(Error::InvalidProof),
        }
    }
}

#[cfg(test)]
mod test;
