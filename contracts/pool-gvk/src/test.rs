// Needed only for the success-path tests below (`alloc::vec::Vec` feeding the
// toy arkworks circuit); the crate itself stays `#![no_std]`.
extern crate alloc;

use crate::{
    Error, ExtData, PoolGvkContract, PoolGvkContractClient, Proof,
    gvk::{self, BabyJubJubPoint, GvkCiphertext, TRACEABLE, VIEW_ONLY},
    merkle_with_history::MerkleDataKey,
    policy,
    pool_gvk::DataKey,
};
use ark_bn254::{Bn254, Fr as ArkFr};
use ark_circom::CircomReduction;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof as ArkProof};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::rand::{SeedableRng, rngs::StdRng};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof};
use contract_types::VerificationKeyBytes;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec, contract, contractimpl,
    crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
    testutils::{Address as _, Events},
    xdr::ToXdr,
};
use soroban_utils::{constants::bn256_modulus, utils::MockToken};

/// Number of levels for the ASP Membership Merkle tree in tests
const ASP_MEMBERSHIP_LEVELS: u32 = 8;

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

fn mk_point(env: &Env, x: u32, y: u32) -> BabyJubJubPoint {
    BabyJubJubPoint {
        x: U256::from_u32(env, x),
        y: U256::from_u32(env, y),
    }
}

/// Helper struct to hold all test setup
struct TestSetup {
    admin: Address,
    token: Address,
    verifier: Address,
    asp_membership_address: Address,
    asp_non_membership_address: Address,
    asp_membership_client: ASPMembershipClient<'static>,
    asp_non_membership_client: ASPNonMembershipClient<'static>,
}

/// Creates and deploys all contracts needed for testing, including a real
/// `CircomGroth16Verifier` and mock token so the transaction-flow tests below
/// can exercise `transact` end to end (mirrors `pool`'s test setup).
fn setup_test_contracts(env: &Env) -> TestSetup {
    let admin = Address::generate(env);

    let asp_membership_address =
        env.register(ASPMembership, (admin.clone(), ASP_MEMBERSHIP_LEVELS));
    let asp_membership_client = ASPMembershipClient::new(env, &asp_membership_address);

    let asp_non_membership_address = env.register(ASPNonMembership, (admin.clone(),));
    let asp_non_membership_client = ASPNonMembershipClient::new(env, &asp_non_membership_address);

    let verifier_address = env.register(CircomGroth16Verifier, ());

    TestSetup {
        admin,
        token: env.register(MockToken, ()),
        verifier: verifier_address,
        asp_membership_address,
        asp_non_membership_address,
        asp_membership_client,
        asp_non_membership_client,
    }
}

fn register_pool_gvk(
    env: &Env,
    setup: &TestSetup,
    maximum_deposit_amount: U256,
    levels: u32,
    policy_flags: u32,
    admin_view_key: BabyJubJubPoint,
    gvk_mode: u32,
) -> Address {
    env.register(
        PoolGvkContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            maximum_deposit_amount,
            levels,
            policy_flags,
            admin_view_key,
            gvk_mode,
        ),
    )
}

#[test]
fn pool_gvk_constructor_sets_state() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let admin_view_key = mk_point(&env, 7, 11);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        max.clone(),
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        admin_view_key.clone(),
        TRACEABLE,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    let stored_admin: Address = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("expected admin to be stored"))
    });
    let stored_max: U256 = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::MaximumDepositAmount)
            .unwrap_or_else(|| panic!("expected maximum deposit amount to be stored"))
    });
    let has_merkle_root = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .has(&MerkleDataKey::CurrentRootIndex)
    });

    assert_eq!(stored_admin, setup.admin);
    assert_eq!(stored_max, max);
    assert!(has_merkle_root);
    assert_eq!(pool.get_admin_view_key(), admin_view_key);
    assert_eq!(pool.get_gvk_mode(), TRACEABLE);
    assert_eq!(
        pool.get_policy_flags(),
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #14)")] // InvalidPolicyFlags = 14
fn pool_gvk_constructor_rejects_invalid_policy_flags() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        !policy::MASK,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #15)")] // InvalidGvkMode = 15
fn pool_gvk_constructor_rejects_invalid_gvk_mode() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        mk_point(&env, 1, 2),
        0,
    );
}

/// `AdminViewKey` is immutable and has no setter, so a key that can never
/// satisfy the circuit permanently bricks the pool: every `transact` would
/// fail at proof verification with no way to fix it. These four cases are the
/// ones catchable without on-chain curve arithmetic.
#[test]
#[should_panic(expected = "Error(Contract, #17)")] // InvalidAdminViewKey = 17
fn pool_gvk_constructor_rejects_non_canonical_admin_view_key_x() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let key = BabyJubJubPoint {
        x: bn256_modulus(&env),
        y: U256::from_u32(&env, 2),
    };
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        key,
        VIEW_ONLY,
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #17)")] // InvalidAdminViewKey = 17
fn pool_gvk_constructor_rejects_non_canonical_admin_view_key_y() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let key = BabyJubJubPoint {
        x: U256::from_u32(&env, 1),
        y: bn256_modulus(&env),
    };
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        key,
        VIEW_ONLY,
    );
}

/// The likely deployment mistake: an all-zero point, which is not even on the
/// curve.
#[test]
#[should_panic(expected = "Error(Contract, #17)")] // InvalidAdminViewKey = 17
fn pool_gvk_constructor_rejects_zero_admin_view_key() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        mk_point(&env, 0, 0),
        VIEW_ONLY,
    );
}

/// `x == 0` also covers the identity `(0, 1)`, which passes `BabyCheck` but is
/// low-order and would be rejected in-circuit on every proof.
#[test]
#[should_panic(expected = "Error(Contract, #17)")] // InvalidAdminViewKey = 17
fn pool_gvk_constructor_rejects_identity_admin_view_key() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        mk_point(&env, 0, 1),
        VIEW_ONLY,
    );
}

/// The check must not be over-tight: `modulus - 1` is a canonical field
/// element and has to be accepted.
#[test]
fn pool_gvk_constructor_accepts_boundary_canonical_admin_view_key() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = bn256_modulus(&env).sub(&U256::from_u32(&env, 1));
    let key = BabyJubJubPoint {
        x: max.clone(),
        y: max.clone(),
    };
    let pool = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        8,
        policy::ALLOWLIST_BIT,
        key,
        VIEW_ONLY,
    );

    let client = PoolGvkContractClient::new(&env, &pool);
    assert_eq!(client.get_admin_view_key().x, max);
}

#[test]
fn pool_gvk_getters_round_trip() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let admin_view_key = mk_point(&env, 3, 4);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT,
        admin_view_key.clone(),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    assert_eq!(pool.get_admin_view_key(), admin_view_key);
    assert_eq!(pool.get_gvk_mode(), VIEW_ONLY);
    assert_eq!(pool.get_policy_flags(), policy::ALLOWLIST_BIT);

    let root = pool.get_root();
    assert!(pool.is_known_root(&root));

    let nullifier = U256::from_u32(&env, 42);
    assert!(!pool.is_spent(&nullifier));

    assert_eq!(
        pool.get_asp_membership_root(),
        setup.asp_membership_client.get_root()
    );
    assert_eq!(
        pool.get_asp_non_membership_root(),
        setup.asp_non_membership_client.get_root()
    );
}

#[test]
fn pool_gvk_update_admin_transfers_control() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 1),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();

    let new_admin = Address::generate(&env);
    pool.update_admin(&new_admin);

    let stored_admin: Address = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("expected admin to be stored"))
    });
    assert_eq!(stored_admin, new_admin);
}

fn mk_bytesn32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

fn mk_ext_data(env: &Env, recipient: Address, ext_amount: i32) -> ExtData {
    ExtData {
        recipient,
        ext_amount: I256::from_i32(env, ext_amount),
        encrypted_output0: Bytes::new(env),
        encrypted_output1: Bytes::new(env),
    }
}

fn compute_ext_hash(env: &Env, ext: &ExtData) -> BytesN<32> {
    let payload = ext.clone().to_xdr(env);
    let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
    let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
    let reduced = digest_u256.rem_euclid(&bn256_modulus(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

/// Create a mock Groth16 proof for testing: a dummy proof with valid curve
/// points. Actual proof validity is not checked in these unit tests, since
/// a real `CircomGroth16Verifier` always rejects a proof this shallow — the
/// tests below all exercise checks that run before or independently of that
/// rejection.
fn mk_mock_groth16_proof(env: &Env) -> Groth16Proof {
    let g1_bytes = {
        let mut bytes = [0u8; 64];
        bytes[31] = 1;
        bytes[63] = 2;
        bytes
    };
    let g2_bytes = {
        let mut bytes = [0u8; 128];
        bytes[31] = 1;
        bytes[63] = 1;
        bytes[95] = 1;
        bytes[127] = 1;
        bytes
    };

    Groth16Proof {
        a: G1Affine::from_array(env, &g1_bytes),
        b: G2Affine::from_array(env, &g2_bytes),
        c: G1Affine::from_array(env, &g1_bytes),
    }
}

fn mk_ciphertext(env: &Env, x: u32, y: u32, c1: u32, c2: u32, c3: u32) -> GvkCiphertext {
    GvkCiphertext {
        r: mk_point(env, x, y),
        c1: U256::from_u32(env, c1),
        c2: U256::from_u32(env, c2),
        c3: U256::from_u32(env, c3),
    }
}

fn mk_output_ciphertexts(env: &Env) -> Vec<GvkCiphertext> {
    let mut v = Vec::new(env);
    v.push_back(mk_ciphertext(env, 20, 21, 22, 23, 24));
    v.push_back(mk_ciphertext(env, 30, 31, 32, 33, 34));
    v
}

/// Build `n` input ciphertexts with distinct, arbitrary values. Only ever
/// called with `n <= 1` in this test module (the fixed single-nullifier
/// scenario `mk_transact_proof` builds), so a fixed lookup table sidesteps
/// `clippy::arithmetic_side_effects` without an unused overflow guard.
fn mk_input_ciphertexts(env: &Env, n: u32) -> Vec<GvkCiphertext> {
    const VALUES: [(u32, u32, u32, u32, u32); 1] = [(10, 11, 12, 13, 14)];
    let mut v = Vec::new(env);
    for &(x, y, c1, c2, c3) in VALUES.iter().take(n as usize) {
        v.push_back(mk_ciphertext(env, x, y, c1, c2, c3));
    }
    v
}

fn asp_roots(setup: &TestSetup) -> (U256, U256) {
    (
        setup.asp_membership_client.get_root(),
        setup.asp_non_membership_client.get_root(),
    )
}

/// Baseline transact proof with valid pool root, ext hash, public amount,
/// and correctly-shaped (but arbitrary-valued) GVK ciphertexts for
/// `gvk_mode`.
fn mk_transact_proof(
    env: &Env,
    pool: &PoolGvkContractClient,
    asp_membership_root: U256,
    asp_non_membership_root: U256,
    nullifier: u32,
    gvk_mode: u32,
) -> (Proof, ExtData) {
    let root = pool.get_root();
    let ext = mk_ext_data(env, Address::generate(env), 0);
    let ext_hash = compute_ext_hash(env, &ext);
    let input_gvk_ciphertexts = if gvk::requires_input_encryption(gvk_mode) {
        mk_input_ciphertexts(env, 1)
    } else {
        Vec::new(env)
    };
    let proof = Proof {
        proof: mk_mock_groth16_proof(env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(env);
            v.push_back(U256::from_u32(env, nullifier));
            v
        },
        output_commitment0: U256::from_u32(env, 0x01),
        output_commitment1: U256::from_u32(env, 0x02),
        public_amount: U256::from_u32(env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(env),
        input_gvk_ciphertexts,
    };
    (proof, ext)
}

fn wrong_asp_root(env: &Env) -> U256 {
    U256::from_u32(env, 0xBAD0_BEEF)
}

#[derive(Clone, Copy, Debug)]
enum PolicyAspRootField {
    Membership,
    NonMembership,
}

fn assert_policy_transact_rejects_wrong_asp_root(
    flags: u32,
    wrong_field: PolicyAspRootField,
    nullifier: u32,
) {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        flags,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);

    let (member_root, non_member_root) = asp_roots(&setup);
    let wrong = wrong_asp_root(&env);
    let (asp_membership_root, asp_non_membership_root) = match wrong_field {
        PolicyAspRootField::Membership => (wrong, non_member_root),
        PolicyAspRootField::NonMembership => (member_root, wrong),
    };
    let (proof, ext) = mk_transact_proof(
        &env,
        &pool,
        asp_membership_root,
        asp_non_membership_root,
        nullifier,
        VIEW_ONLY,
    );

    assert!(
        matches!(
            pool.try_transact(&proof, &ext, &sender),
            Err(Ok(Error::InvalidProof))
        ),
        "expected InvalidProof for flags={} with wrong {wrong_field:?} root",
        flags
    );
}

fn assert_policy_transact_skips_ignored_asp_root_validation(flags: u32, nullifier: u32) {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        flags,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);

    let (member_root, non_member_root) = asp_roots(&setup);
    let non_canonical = bn256_modulus(&env);
    let (asp_membership_root, asp_non_membership_root) = match flags {
        0u32 => (non_canonical.clone(), non_canonical),
        policy::ALLOWLIST_BIT => (member_root, non_canonical),
        policy::BLOCKLIST_BIT => (non_canonical, non_member_root),
        flags if flags == policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT => {
            panic!("AB policy validates both ASP roots")
        }
        _ => panic!("unexpected policy flags in test"),
    };
    let (proof, ext) = mk_transact_proof(
        &env,
        &pool,
        asp_membership_root,
        asp_non_membership_root,
        nullifier,
        VIEW_ONLY,
    );

    assert!(
        !matches!(
            pool.try_transact(&proof, &ext, &sender),
            Err(Ok(Error::InvalidProof))
        ),
        "flags={flags} should not require ASP root validation for the ignored field(s)"
    );
}

#[test]
fn transact_rejects_unknown_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root: U256::from_u32(&env, 0xFF), // not a known root
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xAB));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x01),
        output_commitment1: U256::from_u32(&env, 0x02),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(&env, 0xEE),
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
fn transact_rejects_bad_ext_hash() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xCC));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x03),
        output_commitment1: U256::from_u32(&env, 0x04),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(&env, 0x99), // mismatched hash
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
fn transact_rejects_bad_public_amount() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xDD));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x05),
        output_commitment1: U256::from_u32(&env, 0x06),
        public_amount: U256::from_u32(&env, 1), // should be 0 for ext_amount=0
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
fn transact_rejects_non_canonical_nullifier() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(bn256_modulus(&env));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x07),
        output_commitment1: U256::from_u32(&env, 0x08),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
fn transact_rejects_non_canonical_output_commitment() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xEE));
            v
        },
        output_commitment0: bn256_modulus(&env),
        output_commitment1: U256::from_u32(&env, 0x08),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
fn transact_does_not_reject_boundary_canonical_public_input() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);
    let one = U256::from_u32(&env, 1);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(bn256_modulus(&env).sub(&one));
            v
        },
        output_commitment0: bn256_modulus(&env).sub(&one),
        output_commitment1: U256::from_u32(&env, 0x08),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(!matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
fn transact_rejects_wrong_asp_root_when_flags_require() {
    let cases = [
        (policy::ALLOWLIST_BIT, PolicyAspRootField::Membership, 0xB1),
        (
            policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
            PolicyAspRootField::Membership,
            0xB2,
        ),
        (
            policy::BLOCKLIST_BIT,
            PolicyAspRootField::NonMembership,
            0xB3,
        ),
        (
            policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
            PolicyAspRootField::NonMembership,
            0xB4,
        ),
    ];

    for (flags, wrong_field, nullifier) in cases {
        assert_policy_transact_rejects_wrong_asp_root(flags, wrong_field, nullifier);
    }
}

#[test]
fn transact_skips_asp_root_canonical_validation_when_flags_ignore_field() {
    let cases = [
        (0u32, 0xB5),
        (policy::ALLOWLIST_BIT, 0xB6),
        (policy::BLOCKLIST_BIT, 0xB7),
    ];

    for (flags, nullifier) in cases {
        assert_policy_transact_skips_ignored_asp_root_validation(flags, nullifier);
    }
}

#[test]
fn transact_errors_when_policy_flags_unset() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.as_contract(&pool_id, || {
        env.storage().persistent().remove(&DataKey::PolicyFlags);
    });

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let (member_root, non_member_root) = asp_roots(&setup);
    let (proof, ext) =
        mk_transact_proof(&env, &pool, member_root, non_member_root, 0xB8, VIEW_ONLY);

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NotInitialized))
    ));
}

#[test]
fn transact_rejects_wrong_output_gvk_ciphertext_count() {
    for gvk_mode in [VIEW_ONLY, TRACEABLE] {
        let env = test_env();
        let setup = setup_test_contracts(&env);
        let pool_id = register_pool_gvk(
            &env,
            &setup,
            U256::from_u32(&env, 1000),
            3,
            0,
            mk_point(&env, 1, 2),
            gvk_mode,
        );
        let pool = PoolGvkContractClient::new(&env, &pool_id);
        env.mock_all_auths();
        let sender = Address::generate(&env);
        let (member_root, non_member_root) = asp_roots(&setup);

        let (mut proof, ext) =
            mk_transact_proof(&env, &pool, member_root, non_member_root, 0xC1, gvk_mode);
        // Only one output ciphertext instead of the required two.
        let mut wrong_outputs = Vec::new(&env);
        wrong_outputs.push_back(mk_ciphertext(&env, 1, 2, 3, 4, 5));
        proof.output_gvk_ciphertexts = wrong_outputs;

        assert!(
            matches!(
                pool.try_transact(&proof, &ext, &sender),
                Err(Ok(Error::WrongGvkCiphertextCount))
            ),
            "gvk_mode={gvk_mode} should reject a wrong output ciphertext count"
        );
    }
}

#[test]
fn transact_rejects_wrong_input_gvk_ciphertext_count_when_traceable() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 2),
        TRACEABLE,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);
    let (member_root, non_member_root) = asp_roots(&setup);

    let (mut proof, ext) =
        mk_transact_proof(&env, &pool, member_root, non_member_root, 0xC2, TRACEABLE);
    // Traceable mode requires one input ciphertext per nullifier (one here);
    // leave it empty instead.
    proof.input_gvk_ciphertexts = Vec::new(&env);

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::WrongGvkCiphertextCount))
    ));
}

#[test]
fn transact_rejects_input_gvk_ciphertexts_present_when_view_only() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);
    let (member_root, non_member_root) = asp_roots(&setup);

    let (mut proof, ext) =
        mk_transact_proof(&env, &pool, member_root, non_member_root, 0xC3, VIEW_ONLY);
    // View-only requires zero input ciphertexts; smuggle one in.
    proof.input_gvk_ciphertexts = mk_input_ciphertexts(&env, 1);

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::WrongGvkCiphertextCount))
    ));
}

#[test]
fn transact_rejects_non_canonical_gvk_ciphertext_field() {
    for gvk_mode in [VIEW_ONLY, TRACEABLE] {
        let env = test_env();
        let setup = setup_test_contracts(&env);
        let pool_id = register_pool_gvk(
            &env,
            &setup,
            U256::from_u32(&env, 1000),
            3,
            0,
            mk_point(&env, 1, 2),
            gvk_mode,
        );
        let pool = PoolGvkContractClient::new(&env, &pool_id);
        env.mock_all_auths();
        let sender = Address::generate(&env);
        let (member_root, non_member_root) = asp_roots(&setup);

        let (mut proof, ext) =
            mk_transact_proof(&env, &pool, member_root, non_member_root, 0xC4, gvk_mode);
        let mut bad_output = proof.output_gvk_ciphertexts.get(0).expect("output ct 0");
        bad_output.c1 = bn256_modulus(&env);
        proof.output_gvk_ciphertexts.set(0, bad_output);

        assert!(
            matches!(
                pool.try_transact(&proof, &ext, &sender),
                Err(Ok(Error::NonCanonicalPublicInput))
            ),
            "gvk_mode={gvk_mode} should reject a non-canonical ciphertext field"
        );
    }
}

#[test]
fn transact_does_not_reject_boundary_canonical_gvk_ciphertext_field() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);
    let (member_root, non_member_root) = asp_roots(&setup);
    let one = U256::from_u32(&env, 1);

    let (mut proof, ext) =
        mk_transact_proof(&env, &pool, member_root, non_member_root, 0xC5, VIEW_ONLY);
    let mut boundary_output = proof.output_gvk_ciphertexts.get(0).expect("output ct 0");
    boundary_output.c1 = bn256_modulus(&env).sub(&one);
    proof.output_gvk_ciphertexts.set(0, boundary_output);

    assert!(!matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

/// The caller cannot influence the admin view key `D` fed into the
/// verifier: there is no `D` field on `Proof` at all, so `verify_proof`
/// always injects the contract's own stored `AdminViewKey` regardless of
/// what's passed anywhere else — structurally enforced by `Proof`'s shape,
/// not by a runtime check. This test pins the observable consequence:
/// two pools with different admin view keys but byte-identical transact
/// inputs (same proof, same ext data) are indistinguishable to the caller.
/// Both calls reach the verifier (a real `CircomGroth16Verifier` with no
/// verifying key configured, so it always errors on the public-input
/// count) and fail with the exact same error, regardless of which admin
/// view key the pool holds — because nothing about the call the caller
/// makes changed between the two pools.
fn transact_with_admin_view_key(
    env: &Env,
    setup: &TestSetup,
    admin_view_key: BabyJubJubPoint,
    member_root: U256,
    non_member_root: U256,
) -> bool {
    let pool_id = register_pool_gvk(
        env,
        setup,
        U256::from_u32(env, 1000),
        3,
        0,
        admin_view_key,
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(env);

    let (proof, ext) = mk_transact_proof(env, &pool, member_root, non_member_root, 0xC6, VIEW_ONLY);

    let result = pool.try_transact(&proof, &ext, &sender);
    assert!(result.is_err(), "expected transact to fail: {result:?}");
    matches!(result, Err(Ok(Error::InvalidProof)))
}

#[test]
fn transact_never_accepts_caller_supplied_admin_view_key() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let (member_root, non_member_root) = asp_roots(&setup);

    let is_invalid_proof_a = transact_with_admin_view_key(
        &env,
        &setup,
        mk_point(&env, 1, 2),
        member_root.clone(),
        non_member_root.clone(),
    );
    let is_invalid_proof_b = transact_with_admin_view_key(
        &env,
        &setup,
        mk_point(&env, 99, 100),
        member_root,
        non_member_root,
    );

    assert_eq!(
        is_invalid_proof_a, is_invalid_proof_b,
        "changing the pool's admin view key must not change the caller-observable transact outcome"
    );
}

// No test in this crate can drive a full `transact` success path (there's
// no real Groth16 verifying key to prove against, same limitation `pool`'s
// own suite has — see `test_pool_events_exact_shapes` there), so these
// tests pin `NewCommitmentEvent`/`NewNullifierEvent`'s exact XDR shape (now
// carrying `gvk_ciphertext` directly, no separate memo event) by publishing
// them directly via `env.as_contract`, exactly like `pool`'s precedent.

#[test]
fn pool_gvk_commitment_event_carries_ciphertext() {
    use crate::NewCommitmentEvent;
    use soroban_sdk::events::Event;

    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let commitment = U256::from_u32(&env, 123);
    let encrypted_output = Bytes::from_array(&env, &[0u8; 120]);
    let ciphertext = mk_ciphertext(&env, 20, 21, 22, 23, 24);

    env.as_contract(&pool_id, || {
        NewCommitmentEvent {
            commitment: commitment.clone(),
            index: 0,
            encrypted_output: encrypted_output.clone(),
            gvk_ciphertext: ciphertext.clone(),
        }
        .publish(&env);
    });

    let events = env.events().all();
    assert_eq!(events.events().len(), 1);

    let expected = NewCommitmentEvent {
        commitment,
        index: 0,
        encrypted_output,
        gvk_ciphertext: ciphertext,
    }
    .to_xdr(&env, &pool_id);
    assert_eq!(events.events()[0], expected);
}

#[test]
fn pool_gvk_nullifier_event_carries_ciphertext_only_when_traceable() {
    use crate::NewNullifierEvent;
    use soroban_sdk::events::Event;

    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        0,
        mk_point(&env, 1, 2),
        TRACEABLE,
    );
    let nullifier = U256::from_u32(&env, 456);
    let ciphertext = mk_ciphertext(&env, 10, 11, 12, 13, 14);

    env.as_contract(&pool_id, || {
        NewNullifierEvent {
            nullifier: nullifier.clone(),
            gvk_ciphertext: Some(ciphertext.clone()),
        }
        .publish(&env);
        NewNullifierEvent {
            nullifier: nullifier.clone(),
            gvk_ciphertext: None,
        }
        .publish(&env);
    });

    let events = env.events().all();
    assert_eq!(events.events().len(), 2);

    let expected_traceable = NewNullifierEvent {
        nullifier: nullifier.clone(),
        gvk_ciphertext: Some(ciphertext),
    }
    .to_xdr(&env, &pool_id);
    assert_eq!(events.events()[0], expected_traceable);

    let expected_view_only = NewNullifierEvent {
        nullifier,
        gvk_ciphertext: None,
    }
    .to_xdr(&env, &pool_id);
    assert_eq!(events.events()[1], expected_view_only);
}

// Every test above either fails before `verify_proof` is reached, or checks
// event *shapes* without going through `transact` at all — because the
// workspace's shared `CircomGroth16Verifier` (registered by
// `setup_test_contracts`) embeds a compile-time verification key for an
// 11-public-input policy circuit (`testdata/policy_tx_2_2_AB_vk.json`, wired
// via `.cargo/config.toml`'s `VERIFIER_VK_JSON`), which can never match a
// GVK-shaped public input vector (19+ elements once the ciphertext tail is
// included) — every call through it fails on `Groth16Error::
// MalformedPublicInputs` before the pairing check ever runs.
//
// To actually observe a *successful* `transact` and its GVK-carrying events,
// this section deploys `TestVerifier`, a minimal Groth16 verifier that stores
// an arbitrary verification key supplied at construction (rather than one
// baked in at compile time), and proves a real Groth16 proof against a
// trivial toy circuit (`NInputCircuit`, generalizing
// `circom_groth16_verifier`'s own test fixture, `ElevenInputCircuit`) whose
// public inputs are unconstrained except the first, tied to a matching
// witness — so it's satisfiable for any chosen values, letting the fixture
// match `verify_proof`'s exact public-input sequence for a specific,
// concrete transaction.

/// Minimal Groth16 verifier storing an arbitrary verification key supplied at
/// construction. Unlike `circom_groth16_verifier::CircomGroth16Verifier`
/// (whose VK is embedded at compile time, fixed workspace-wide to an
/// 11-public-input policy circuit), this lets each test prove against its
/// own toy circuit sized to match a specific GVK public-input vector.
/// Test-only scaffolding: the pairing-check logic is a duplicate of
/// `circom_groth16_verifier::verify_with_vk`, which is private to its crate.
#[contract]
struct TestVerifier;

#[contractimpl]
impl TestVerifier {
    pub fn __constructor(env: Env, vk: VerificationKeyBytes) {
        env.storage()
            .instance()
            .set(&soroban_sdk::symbol_short!("vk"), &vk);
    }

    pub fn verify(
        env: Env,
        proof: Groth16Proof,
        public_inputs: Vec<soroban_sdk::crypto::bn254::Bn254Fr>,
    ) -> Result<bool, contract_types::Groth16Error> {
        use contract_types::Groth16Error;

        let vk: VerificationKeyBytes = env
            .storage()
            .instance()
            .get(&soroban_sdk::symbol_short!("vk"))
            .expect("TestVerifier not initialized");
        let mut ic: Vec<G1Affine> = Vec::new(&env);
        for bytes in vk.ic.iter() {
            ic.push_back(G1Affine::from_bytes(bytes));
        }
        let alpha = G1Affine::from_bytes(vk.alpha);
        let beta = G2Affine::from_bytes(vk.beta);
        let gamma = G2Affine::from_bytes(vk.gamma);
        let delta = G2Affine::from_bytes(vk.delta);

        let bn = env.crypto().bn254();
        if public_inputs.len().checked_add(1) != Some(ic.len()) {
            return Err(Groth16Error::MalformedPublicInputs);
        }
        let mut vk_x = ic.get(0).ok_or(Groth16Error::MalformedPublicInputs)?;
        for i in 0..public_inputs.len() {
            let s = public_inputs
                .get(i)
                .ok_or(Groth16Error::MalformedPublicInputs)?;
            let ic_idx = i
                .checked_add(1)
                .ok_or(Groth16Error::MalformedPublicInputs)?;
            let v = ic.get(ic_idx).ok_or(Groth16Error::MalformedPublicInputs)?;
            let prod = bn.g1_mul(&v, &s);
            vk_x = bn.g1_add(&vk_x, &prod);
        }

        #[allow(clippy::arithmetic_side_effects)]
        let neg_a = -proof.a;
        let g1_points = soroban_sdk::vec![&env, neg_a, alpha, vk_x, proof.c];
        let g2_points = soroban_sdk::vec![&env, proof.b, beta, gamma, delta];
        if bn.pairing_check(g1_points, g2_points) {
            Ok(true)
        } else {
            Err(Groth16Error::InvalidProof)
        }
    }
}

/// A toy circuit exposing `inputs.len()` public inputs. Only the first is
/// constrained (tied to a matching witness), so it's satisfiable for any
/// chosen values — generalizes `circom_groth16_verifier::test::
/// ElevenInputCircuit` to an arbitrary length.
#[derive(Clone)]
struct NInputCircuit {
    inputs: alloc::vec::Vec<ArkFr>,
}

impl ConstraintSynthesizer<ArkFr> for NInputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ArkFr>) -> Result<(), SynthesisError> {
        let mut input_vars = alloc::vec::Vec::with_capacity(self.inputs.len());
        for value in &self.inputs {
            input_vars.push(cs.new_input_variable(|| Ok(*value))?);
        }
        let witness = cs.new_witness_variable(|| Ok(self.inputs[0]))?;
        let a_lc = witness.into();
        let b_lc = Variable::One.into();
        let c_lc = input_vars[0].into();
        cs.enforce_r1cs_constraint(|| a_lc, || b_lc, || c_lc)?;
        Ok(())
    }
}

fn seeded_rng() -> StdRng {
    StdRng::seed_from_u64(7)
}

fn groth16_proof_from_ark(env: &Env, proof: &ArkProof<Bn254>) -> Groth16Proof {
    Groth16Proof {
        a: G1Affine::from_bytes(BytesN::from_array(
            env,
            &soroban_utils::g1_bytes_from_ark(proof.a),
        )),
        b: G2Affine::from_bytes(BytesN::from_array(
            env,
            &soroban_utils::g2_bytes_from_ark(proof.b),
        )),
        c: G1Affine::from_bytes(BytesN::from_array(
            env,
            &soroban_utils::g1_bytes_from_ark(proof.c),
        )),
    }
}

/// Generate a real Groth16 (VK, proof) pair proving `NInputCircuit(values)`,
/// i.e. one that verifies if and only if the public inputs equal `values` in
/// this exact order.
fn groth16_fixture_for(env: &Env, values: &[ArkFr]) -> (VerificationKeyBytes, Groth16Proof) {
    let mut rng = seeded_rng();
    let circuit = NInputCircuit {
        inputs: values.to_vec(),
    };
    let params = Groth16::<Bn254, CircomReduction>::generate_random_parameters_with_reduction(
        circuit.clone(),
        &mut rng,
    )
    .expect("toy circuit params failed to generate");
    let proof = Groth16::<Bn254, CircomReduction>::create_random_proof_with_reduction(
        circuit, &params, &mut rng,
    )
    .expect("toy circuit proof failed to generate");
    let vk_bytes = soroban_utils::vk_bytes_from_ark(env, &params.vk);
    (vk_bytes, groth16_proof_from_ark(env, &proof))
}

fn ark_fr_from_u256(v: &U256) -> ArkFr {
    let mut buf = [0u8; 32];
    v.to_be_bytes().copy_into_slice(&mut buf);
    ArkFr::from_be_bytes_mod_order(&buf)
}

fn ark_fr_from_bytesn32(v: &BytesN<32>) -> ArkFr {
    ArkFr::from_be_bytes_mod_order(&v.to_array())
}

/// Independently mirrors `PoolGvkContract::verify_proof`'s public-input
/// assembly order (ciphertext tail first, then `D, nonce, root,
/// publicAmount, extDataHash, inputNullifier[], outputCommitment[]` — no ASP
/// roots, since every test using this helper registers with `policy_flags =
/// 0`) so the toy-circuit fixture and the real contract call are checked
/// against the same sequence without one implementation calling the other.
fn expected_ark_public_inputs(
    proof: &Proof,
    admin_view_key: &BabyJubJubPoint,
) -> alloc::vec::Vec<ArkFr> {
    let mut ciphertexts: alloc::vec::Vec<GvkCiphertext> = alloc::vec::Vec::new();
    for ct in proof.input_gvk_ciphertexts.iter() {
        ciphertexts.push(ct);
    }
    for ct in proof.output_gvk_ciphertexts.iter() {
        ciphertexts.push(ct);
    }

    let mut result: alloc::vec::Vec<ArkFr> = alloc::vec::Vec::new();
    for ct in &ciphertexts {
        result.push(ark_fr_from_u256(&ct.r.x));
        result.push(ark_fr_from_u256(&ct.r.y));
    }
    for ct in &ciphertexts {
        result.push(ark_fr_from_u256(&ct.c1));
    }
    for ct in &ciphertexts {
        result.push(ark_fr_from_u256(&ct.c2));
    }
    for ct in &ciphertexts {
        result.push(ark_fr_from_u256(&ct.c3));
    }

    result.push(ark_fr_from_u256(&admin_view_key.x));
    result.push(ark_fr_from_u256(&admin_view_key.y));
    result.push(ark_fr_from_bytesn32(&proof.ext_data_hash)); // nonce
    result.push(ark_fr_from_u256(&proof.root));
    result.push(ark_fr_from_u256(&proof.public_amount));
    result.push(ark_fr_from_bytesn32(&proof.ext_data_hash)); // ext_data_hash

    for n in proof.input_nullifiers.iter() {
        result.push(ark_fr_from_u256(&n));
    }
    result.push(ark_fr_from_u256(&proof.output_commitment0));
    result.push(ark_fr_from_u256(&proof.output_commitment1));

    result
}

/// Builds a pool, a matching Groth16 fixture, and a ready-to-submit
/// `(Proof, ExtData)` pair for `gvk_mode`/`ext_amount`, without calling
/// `transact`.
fn build_gvk_transact(
    gvk_mode: u32,
    nullifier: u32,
    ext_amount: i32,
    maximum_deposit_amount: u32,
) -> (Env, PoolGvkContractClient<'static>, Proof, ExtData, Address) {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let admin_view_key = mk_point(&env, 1, 2);
    let levels = 3u32;

    // Root is a pure function of `levels` (the empty-tree root), so it can be
    // read off a throwaway pool sharing the same `levels`, before the
    // real, fixture-matched verifier address is known.
    let throwaway_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, maximum_deposit_amount),
        levels,
        0,
        admin_view_key.clone(),
        gvk_mode,
    );
    let root = PoolGvkContractClient::new(&env, &throwaway_id).get_root();

    let ext = mk_ext_data(&env, Address::generate(&env), ext_amount);
    let ext_hash = compute_ext_hash(&env, &ext);
    let input_gvk_ciphertexts = if gvk::requires_input_encryption(gvk_mode) {
        mk_input_ciphertexts(&env, 1)
    } else {
        Vec::new(&env)
    };

    let mut input_nullifiers: Vec<U256> = Vec::new(&env);
    input_nullifiers.push_back(U256::from_u32(&env, nullifier));

    let public_amount = pool_core::amounts::calculate_public_amount(&env, ext.ext_amount.clone())
        .expect("ext_amount within the 2^248 bound used by these tests");

    let mut proof = Proof {
        proof: mk_mock_groth16_proof(&env), // placeholder, replaced below
        root,
        input_nullifiers,
        output_commitment0: U256::from_u32(&env, 0x01),
        output_commitment1: U256::from_u32(&env, 0x02),
        public_amount,
        ext_data_hash: ext_hash,
        asp_membership_root: U256::from_u32(&env, 0),
        asp_non_membership_root: U256::from_u32(&env, 0),
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts,
    };

    let values = expected_ark_public_inputs(&proof, &admin_view_key);
    let (vk_bytes, real_proof) = groth16_fixture_for(&env, &values);
    proof.proof = real_proof;

    let verifier_id = env.register(TestVerifier, (vk_bytes,));

    let pool_id = env.register(
        PoolGvkContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            verifier_id,
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            U256::from_u32(&env, maximum_deposit_amount),
            levels,
            0u32,
            admin_view_key,
            gvk_mode,
        ),
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);
    env.mock_all_auths();
    let sender = Address::generate(&env);

    (env, pool, proof, ext, sender)
}

/// Runs a full successful `transact` for `gvk_mode`, using a `TestVerifier`
/// proving a toy circuit matched to this exact call's public inputs, and
/// returns the pool address for the caller to inspect emitted events on.
fn run_successful_gvk_transact(gvk_mode: u32, nullifier: u32) -> (Env, Address /* pool_id */) {
    let (env, pool, proof, ext, sender) = build_gvk_transact(gvk_mode, nullifier, 0, 1000);
    let pool_id = pool.address.clone();

    let result = pool.try_transact(&proof, &ext, &sender);
    assert!(
        result.is_ok(),
        "expected transact to succeed with a matching toy-circuit proof: {result:?}"
    );

    (env, pool_id)
}

#[test]
fn transact_accepts_correct_view_only_ciphertexts_and_emits_commitment_events() {
    use crate::NewCommitmentEvent;
    use soroban_sdk::events::Event;

    let (env, pool_id) = run_successful_gvk_transact(VIEW_ONLY, 0xE1);
    let events = env.events().all().filter_by_contract(&pool_id);
    let events = events.events();

    // Two output commitments, each carrying its GVK ciphertext directly; no
    // nullifier-side ciphertext (view-only never encrypts inputs).
    let output_ciphertexts = mk_output_ciphertexts(&env);
    let expected0 = NewCommitmentEvent {
        commitment: U256::from_u32(&env, 0x01),
        index: 0,
        encrypted_output: Bytes::new(&env),
        gvk_ciphertext: output_ciphertexts.get(0).expect("output ct 0"),
    }
    .to_xdr(&env, &pool_id);
    let expected1 = NewCommitmentEvent {
        commitment: U256::from_u32(&env, 0x02),
        index: 1,
        encrypted_output: Bytes::new(&env),
        gvk_ciphertext: output_ciphertexts.get(1).expect("output ct 1"),
    }
    .to_xdr(&env, &pool_id);

    assert!(
        events.contains(&expected0),
        "missing NewCommitmentEvent+ciphertext for output_commitment0"
    );
    assert!(
        events.contains(&expected1),
        "missing NewCommitmentEvent+ciphertext for output_commitment1"
    );
}

#[test]
fn transact_accepts_correct_traceable_ciphertexts_and_emits_all_events() {
    use crate::{NewCommitmentEvent, NewNullifierEvent};
    use soroban_sdk::events::Event;

    let (env, pool_id) = run_successful_gvk_transact(TRACEABLE, 0xE2);
    let events = env.events().all().filter_by_contract(&pool_id);
    let events = events.events();

    let output_ciphertexts = mk_output_ciphertexts(&env);
    let input_ciphertexts = mk_input_ciphertexts(&env, 1);

    let expected_output0 = NewCommitmentEvent {
        commitment: U256::from_u32(&env, 0x01),
        index: 0,
        encrypted_output: Bytes::new(&env),
        gvk_ciphertext: output_ciphertexts.get(0).expect("output ct 0"),
    }
    .to_xdr(&env, &pool_id);
    let expected_output1 = NewCommitmentEvent {
        commitment: U256::from_u32(&env, 0x02),
        index: 1,
        encrypted_output: Bytes::new(&env),
        gvk_ciphertext: output_ciphertexts.get(1).expect("output ct 1"),
    }
    .to_xdr(&env, &pool_id);
    let expected_nullifier = NewNullifierEvent {
        nullifier: U256::from_u32(&env, 0xE2),
        gvk_ciphertext: Some(input_ciphertexts.get(0).expect("input ct 0")),
    }
    .to_xdr(&env, &pool_id);

    assert!(
        events.contains(&expected_output0),
        "missing NewCommitmentEvent+ciphertext for output_commitment0"
    );
    assert!(
        events.contains(&expected_output1),
        "missing NewCommitmentEvent+ciphertext for output_commitment1"
    );
    assert!(
        events.contains(&expected_nullifier),
        "missing NewNullifierEvent+ciphertext for the traceable input nullifier"
    );
}

#[test]
fn transact_accepts_positive_ext_amount_deposit() {
    let (_env, pool, proof, ext, sender) = build_gvk_transact(VIEW_ONLY, 0xE3, 50, 1000);

    let result = pool.try_transact(&proof, &ext, &sender);
    assert!(
        result.is_ok(),
        "expected transact to succeed on the deposit path (ext_amount > 0): {result:?}"
    );
}

#[test]
fn transact_accepts_negative_ext_amount_withdrawal() {
    let (_env, pool, proof, ext, sender) = build_gvk_transact(VIEW_ONLY, 0xE4, -50, 1000);

    let result = pool.try_transact(&proof, &ext, &sender);
    assert!(
        result.is_ok(),
        "expected transact to succeed on the withdrawal path (ext_amount < 0): {result:?}"
    );
}

#[test]
fn transact_rejects_deposit_over_maximum() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool_gvk(
        &env,
        &setup,
        U256::from_u32(&env, 100),
        3,
        0,
        mk_point(&env, 1, 2),
        VIEW_ONLY,
    );
    let pool = PoolGvkContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let ext = mk_ext_data(&env, Address::generate(&env), 101); // exceeds the 100 maximum
    let (asp_membership_root, asp_non_membership_root) = asp_roots(&setup);

    // Mock proof, `transact` rejects the deposit before `internal_transact` is
    // reached, so the proof itself never needs to be valid.
    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root: pool.get_root(),
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xD1));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x01),
        output_commitment1: U256::from_u32(&env, 0x02),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: compute_ext_hash(&env, &ext),
        asp_membership_root,
        asp_non_membership_root,
        output_gvk_ciphertexts: mk_output_ciphertexts(&env),
        input_gvk_ciphertexts: Vec::new(&env),
    };

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::WrongExtAmount))
    ));
}

/// Replaying the same nullifier must be rejected
#[test]
fn transact_rejects_replayed_nullifier() {
    let (_env, pool, proof, ext, sender) = build_gvk_transact(VIEW_ONLY, 0xE5, 0, 1000);

    let first = pool.try_transact(&proof, &ext, &sender);
    assert!(
        first.is_ok(),
        "expected the first transact to succeed: {first:?}"
    );

    let second = pool.try_transact(&proof, &ext, &sender);
    assert!(
        matches!(second, Err(Ok(Error::AlreadySpentNullifier))),
        "expected replaying the same nullifier to be rejected, got {second:?}"
    );
}
