use crate::{
    Error, ExtData, PoolGvkContract, PoolGvkContractClient, Proof,
    gvk::{self, BabyJubJubPoint, GvkCiphertext, TRACEABLE, VIEW_ONLY},
    merkle_with_history::MerkleDataKey,
    policy,
    pool_gvk::DataKey,
};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec,
    crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
    testutils::Address as _,
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

// ========== Transaction flow ==========

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
    let (proof, ext) = mk_transact_proof(
        &env,
        &pool,
        member_root,
        non_member_root,
        0xB8,
        VIEW_ONLY,
    );

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
