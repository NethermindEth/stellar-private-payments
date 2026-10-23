extern crate std;

use super::*;
use contract_types::Groth16Error;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, String, Vec,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    symbol_short,
    testutils::{Deployer as _, Events as _},
};
use soroban_utils::{MAX_EXTENSION_LEDGERS, constants::BN256_MOD_BYTES};
use std::{format, string::String as StdString};

fn test_env() -> Env {
    #[cfg(miri)]
    {
        use soroban_sdk::testutils::EnvTestConfig;
        Env::new_with_config(EnvTestConfig {
            capture_snapshot_at_drop: false,
        })
    }
    #[cfg(not(miri))]
    {
        Env::default()
    }
}

const KDF_DOMAIN: &str = "tests";

/// Accepts every proof and keeps the public inputs it was given.
#[contract]
struct RecordingVerifier;

#[contractimpl]
impl RecordingVerifier {
    pub fn verify(
        env: Env,
        _proof: Groth16Proof,
        public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error> {
        env.storage()
            .instance()
            .set(&symbol_short!("inputs"), &public_inputs);
        Ok(true)
    }
}

/// Refuses every proof with a code that is also a registry error code.
#[contract]
struct RejectingVerifier;

#[contractimpl]
impl RejectingVerifier {
    pub fn verify(
        _env: Env,
        _proof: Groth16Proof,
        _public_inputs: Vec<Bn254Fr>,
    ) -> Result<bool, Groth16Error> {
        Err(Groth16Error::MalformedPublicInputs)
    }
}

struct Setup {
    env: Env,
    registry: Address,
    verifier: Address,
}

impl Setup {
    fn new() -> Self {
        let env = test_env();
        let verifier = env.register(RecordingVerifier, ());
        Self::with_verifier(env, verifier)
    }

    fn with_verifier(env: Env, verifier: Address) -> Self {
        let registry = env.register(
            PublicKeyRegistry,
            (String::from_str(&env, KDF_DOMAIN), verifier.clone()),
        );
        env.mock_all_auths();
        Self {
            env,
            registry,
            verifier,
        }
    }

    fn client(&self) -> PublicKeyRegistryClient<'_> {
        PublicKeyRegistryClient::new(&self.env, &self.registry)
    }

    fn stored(&self, owner: &Address) -> Option<Registration> {
        self.env.as_contract(&self.registry, || {
            self.env
                .storage()
                .persistent()
                .get(&DataKey::Registration(owner.clone()))
        })
    }

    fn verified_inputs(&self) -> Option<Vec<Bn254Fr>> {
        self.env.as_contract(&self.verifier, || {
            self.env.storage().instance().get(&symbol_short!("inputs"))
        })
    }
}

/// An account holder: the owner's master key, the encryption key and the note
/// key.
struct Registrant {
    owner: SigningKey,
    encryption: SigningKey,
    note_key: [u8; 32],
}

impl Registrant {
    /// `seed` must stay below 0x30 so that the note key is below r.
    fn new(seed: u8) -> Self {
        Self {
            owner: SigningKey::from_bytes(&[seed; 32]),
            encryption: SigningKey::from_bytes(&[seed ^ 0xff; 32]),
            note_key: [seed; 32],
        }
    }

    fn address(&self, env: &Env) -> Address {
        let key = BytesN::from_array(env, &self.owner.verifying_key().to_bytes());
        AddressPayload::AccountIdPublicKeyEd25519(key).to_address(env)
    }

    fn account(&self, env: &Env) -> Account {
        Account {
            owner: self.address(env),
            encryption_key: Bytes::from_array(env, &self.encryption.verifying_key().to_bytes()),
            note_key: Bytes::from_array(env, &self.note_key),
        }
    }

    /// Proofs for `account` at `registry`, with a placeholder Groth16 proof.
    fn prove(&self, env: &Env, registry: &Address, account: &Account) -> KeyOwnershipProof {
        let digest = expected_digest(registry, account);
        KeyOwnershipProof {
            note_key_proof: placeholder_proof(env),
            encryption_key_signature: BytesN::from_array(
                env,
                &self
                    .encryption
                    .sign(&encryption_challenge(&digest))
                    .to_bytes(),
            ),
            owner_signature: BytesN::from_array(env, &self.owner.sign(&digest).to_bytes()),
        }
    }
}

fn placeholder_proof(env: &Env) -> Groth16Proof {
    Groth16Proof {
        a: Bn254G1Affine::from_array(env, &[0u8; 64]),
        b: Bn254G2Affine::from_array(env, &[0u8; 128]),
        c: Bn254G1Affine::from_array(env, &[0u8; 64]),
    }
}

fn strkey(address: &Address) -> StdString {
    let strkey = address.to_string();
    let mut bytes = std::vec![0u8; strkey.len() as usize];
    strkey.copy_into_slice(&mut bytes);
    StdString::from_utf8(bytes).expect("strkeys are ASCII")
}

fn hex(bytes: &Bytes) -> StdString {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Built without the contract's helpers, so the tests pin the format.

fn expected_message(registry: &Address, account: &Account) -> StdString {
    format!(
        "Privacy Pool Key Registration [v1]\nRegistry: {}\nAccount: {}\nNote key: 0x{}\nEncryption key (Ed25519): 0x{}",
        strkey(registry),
        strkey(&account.owner),
        hex(&account.note_key),
        hex(&account.encryption_key),
    )
}

fn expected_digest(registry: &Address, account: &Account) -> [u8; 32] {
    let mut payload = b"Stellar Signed Message:\n".to_vec();
    payload.extend_from_slice(expected_message(registry, account).as_bytes());
    Sha256::digest(payload).into()
}

fn encryption_challenge(digest: &[u8; 32]) -> [u8; 32] {
    let mut payload = b"privacy-pool/registry/encryption-key/v1".to_vec();
    payload.extend_from_slice(digest);
    Sha256::digest(payload).into()
}

/// Little-endian bytes of the big-endian `value`.
fn le(mut value: [u8; 32]) -> [u8; 32] {
    value.reverse();
    value
}

#[test]
fn register_saves_registration() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);

    setup.client().register(&account, &proof);

    let stored = setup
        .stored(&account.owner)
        .expect("registration should be stored");
    assert_eq!(stored.encryption_key, account.encryption_key);
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn register_passes_note_key_and_registration_hash_to_the_verifier() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);

    setup.client().register(&account, &proof);

    let digest = expected_digest(&setup.registry, &account);
    let expected = Vec::from_array(
        env,
        [
            Bn254Fr::from_bytes(BytesN::from_array(env, &le(registrant.note_key))),
            Bn254Fr::from_bytes(BytesN::from_array(env, &digest)),
        ],
    );
    assert_eq!(setup.verified_inputs(), Some(expected));
}

#[test]
fn registration_message_matches_the_documented_format() {
    let setup = Setup::new();
    let env = &setup.env;
    let account = Registrant::new(0x11).account(env);

    let message = registration_message(env, &setup.registry, &account);

    let expected = expected_message(&setup.registry, &account);
    assert_eq!(message, Bytes::from_slice(env, expected.as_bytes()));
    assert_eq!(
        registration_digest(env, &message).to_array(),
        expected_digest(&setup.registry, &account)
    );
}

#[test]
fn duplicate_registration_is_noop() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);

    setup.client().register(&account, &proof);
    let events_after_first = env.events().all().events().len();
    // The same keys again need no valid proof: nothing changes.
    let unsigned = KeyOwnershipProof {
        note_key_proof: placeholder_proof(env),
        encryption_key_signature: BytesN::from_array(env, &[0u8; 64]),
        owner_signature: BytesN::from_array(env, &[0u8; 64]),
    };
    setup.client().register(&account, &unsigned);
    let events_after_second = env.events().all().events().len();

    assert_eq!(events_after_first, 1);
    assert_eq!(events_after_second, 0);
    let stored = setup
        .stored(&account.owner)
        .expect("registration should be stored");
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn registering_different_keys_is_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let initial = registrant.account(env);
    setup
        .client()
        .register(&initial, &registrant.prove(env, &setup.registry, &initial));

    let rotated = Registrant {
        note_key: [0x22; 32],
        ..registrant
    };
    let rotated_account = rotated.account(env);
    let proof = rotated.prove(env, &setup.registry, &rotated_account);
    let result = setup.client().try_register(&rotated_account, &proof);

    assert_eq!(result, Err(Ok(Error::AlreadyRegistered)));
    let stored = setup
        .stored(&initial.owner)
        .expect("registration should be stored");
    assert_eq!(stored.note_key, initial.note_key);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn register_requires_owner_auth() {
    let env = test_env();
    let verifier = env.register(RecordingVerifier, ());
    let registry = env.register(
        PublicKeyRegistry,
        (String::from_str(&env, KDF_DOMAIN), verifier),
    );
    let registrant = Registrant::new(0x11);
    let account = registrant.account(&env);
    let proof = registrant.prove(&env, &registry, &account);

    PublicKeyRegistryClient::new(&env, &registry).register(&account, &proof);
}

#[test]
fn keys_that_are_not_32_bytes_are_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);

    for (encryption_len, note_len) in [(31, 32), (33, 32), (32, 31), (32, 33)] {
        let mut account = registrant.account(env);
        account.encryption_key = Bytes::from_slice(env, &[0x11; 33][..encryption_len]);
        account.note_key = Bytes::from_slice(env, &[0x11; 33][..note_len]);
        let proof = registrant.prove(env, &setup.registry, &account);

        let result = setup.client().try_register(&account, &proof);

        assert_eq!(result, Err(Ok(Error::InvalidKeyLength)));
    }
}

#[test]
fn contract_owner_is_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let mut account = registrant.account(env);
    account.owner = setup.verifier.clone();
    let proof = registrant.prove(env, &setup.registry, &account);

    let result = setup.client().try_register(&account, &proof);

    assert_eq!(result, Err(Ok(Error::OwnerNotAccount)));
}

#[test]
fn note_key_must_be_below_the_field_modulus() {
    let setup = Setup::new();
    let env = &setup.env;

    let at_modulus = Registrant {
        note_key: le(BN256_MOD_BYTES),
        ..Registrant::new(0x11)
    };
    let account = at_modulus.account(env);
    let proof = at_modulus.prove(env, &setup.registry, &account);
    assert_eq!(
        setup.client().try_register(&account, &proof),
        Err(Ok(Error::NonCanonicalNoteKey))
    );

    let mut below = BN256_MOD_BYTES;
    below[31] = 0;
    let below_modulus = Registrant {
        note_key: le(below),
        ..Registrant::new(0x12)
    };
    let account = below_modulus.account(env);
    let proof = below_modulus.prove(env, &setup.registry, &account);
    setup.client().register(&account, &proof);
}

#[test]
fn encryption_key_y_must_be_below_the_field_modulus() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let mut p = [0xff; 32];
    p[0] = 0x7f;
    p[31] = 0xed;

    for sign_bit in [0x00, 0x80] {
        let mut key = le(p);
        key[31] |= sign_bit;
        let mut account = registrant.account(env);
        account.encryption_key = Bytes::from_array(env, &key);
        let proof = registrant.prove(env, &setup.registry, &account);

        let result = setup.client().try_register(&account, &proof);

        assert_eq!(result, Err(Ok(Error::NonCanonicalEncryptionKey)));
    }
}

/// Registers `account` with `proof`, which must trap in a signature check.
fn register_with_bad_signature(setup: &Setup, account: &Account, proof: &KeyOwnershipProof) {
    setup.client().register(account, proof);
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn owner_signature_is_required() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let mut proof = registrant.prove(env, &setup.registry, &account);
    proof.owner_signature = BytesN::from_array(env, &[0u8; 64]);

    register_with_bad_signature(&setup, &account, &proof);
}

/// A co-signer can authorize the transaction, but can't sign for the master
/// key.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn owner_signature_by_another_key_is_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let mut proof = registrant.prove(env, &setup.registry, &account);
    let cosigner = SigningKey::from_bytes(&[0x99; 32]);
    let digest = expected_digest(&setup.registry, &account);
    proof.owner_signature = BytesN::from_array(env, &cosigner.sign(&digest).to_bytes());

    register_with_bad_signature(&setup, &account, &proof);
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn signatures_for_another_registry_are_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let other_registry = env.register(
        PublicKeyRegistry,
        (String::from_str(env, KDF_DOMAIN), setup.verifier.clone()),
    );
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &other_registry, &account);

    register_with_bad_signature(&setup, &account, &proof);
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn signatures_for_another_account_are_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let mut other_account = registrant.account(env);
    other_account.owner = Registrant::new(0x12).address(env);
    let proof = registrant.prove(env, &setup.registry, &other_account);

    register_with_bad_signature(&setup, &account, &proof);
}

#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn encryption_signature_by_another_key_is_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let mut proof = registrant.prove(env, &setup.registry, &account);
    let challenge = encryption_challenge(&expected_digest(&setup.registry, &account));
    let other = SigningKey::from_bytes(&[0x99; 32]);
    proof.encryption_key_signature = BytesN::from_array(env, &other.sign(&challenge).to_bytes());

    register_with_bad_signature(&setup, &account, &proof);
}

/// Without the tag, the encryption key would sign a plain SEP-53 digest.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn encryption_signature_must_cover_the_tag() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let mut proof = registrant.prove(env, &setup.registry, &account);
    let digest = expected_digest(&setup.registry, &account);
    proof.encryption_key_signature =
        BytesN::from_array(env, &registrant.encryption.sign(&digest).to_bytes());

    register_with_bad_signature(&setup, &account, &proof);
}

/// Each key's signature is checked against the field it is registered in.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn swapped_keys_are_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let swapped = Account {
        owner: account.owner.clone(),
        encryption_key: account.note_key.clone(),
        note_key: account.encryption_key.clone(),
    };
    // The encryption key's bytes must pass as a canonical note key, or the
    // registry refuses them before any signature check.
    assert!(
        registrant.encryption.verifying_key().to_bytes()[31] < 0x30,
        "pick another seed"
    );
    let proof = registrant.prove(env, &setup.registry, &swapped);

    register_with_bad_signature(&setup, &swapped, &proof);
}

/// The identity point accepts `(R, s) = (identity, 0)` under a cofactorless
/// check. The host's strict verification refuses small-order keys.
#[test]
#[should_panic(expected = "Error(Crypto, InvalidInput)")]
fn small_order_encryption_key_is_refused() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut account = registrant.account(env);
    account.encryption_key = Bytes::from_array(env, &identity);
    let mut proof = registrant.prove(env, &setup.registry, &account);
    let mut forged = [0u8; 64];
    forged[0] = 1;
    proof.encryption_key_signature = BytesN::from_array(env, &forged);

    register_with_bad_signature(&setup, &account, &proof);
}

#[test]
fn verifier_rejection_is_reported_as_invalid_proof() {
    let env = test_env();
    let verifier = env.register(RejectingVerifier, ());
    let setup = Setup::with_verifier(env, verifier);
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);

    let result = setup.client().try_register(&account, &proof);

    // MalformedPublicInputs shares code 1 with InvalidKeyLength.
    assert_eq!(result, Err(Ok(Error::InvalidProof)));
    assert_eq!(setup.stored(&account.owner), None);
}

#[test]
fn error_codes_are_stable() {
    assert_eq!(Error::InvalidKeyLength as u32, 1);
    assert_eq!(Error::OwnerNotAccount as u32, 2);
    assert_eq!(Error::NonCanonicalNoteKey as u32, 3);
    assert_eq!(Error::NonCanonicalEncryptionKey as u32, 4);
    assert_eq!(Error::AlreadyRegistered as u32, 5);
    assert_eq!(Error::InvalidProof as u32, 6);
}

#[test]
fn test_public_key_event_exact_shape() {
    use soroban_sdk::events::Event;
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);

    setup.client().register(&account, &proof);

    let events = env.events().all();
    assert_eq!(events.events().len(), 1);

    let expected = PublicKeyEvent {
        owner: account.owner,
        encryption_key: account.encryption_key,
        note_key: account.note_key,
    }
    .to_xdr(env, &setup.registry);
    assert_eq!(events.events()[0], expected);
}

#[test]
fn getters_return_constructor_values() {
    let setup = Setup::new();
    assert_eq!(
        setup.client().get_kdf_domain(),
        String::from_str(&setup.env, KDF_DOMAIN)
    );
    assert_eq!(setup.client().get_verifier(), setup.verifier);
}

#[test]
fn register_renews_the_instance() {
    let setup = Setup::new();
    let env = &setup.env;
    let registrant = Registrant::new(0x11);
    let account = registrant.account(env);
    let proof = registrant.prove(env, &setup.registry, &account);
    setup.client().register(&account, &proof);
    let before = env.deployer().get_contract_instance_ttl(&setup.registry);

    // A registration that changes nothing still renews.
    setup.client().register(&account, &proof);

    assert_eq!(
        env.deployer().get_contract_instance_ttl(&setup.registry),
        before.saturating_add(MAX_EXTENSION_LEDGERS)
    );
}
