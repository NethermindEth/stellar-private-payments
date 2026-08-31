use crate::{
    Error, ExtData, PoolContract, PoolContractClient, Proof,
    merkle_with_history::{MerkleDataKey, MerkleTreeWithHistory},
    policy,
};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof};
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, U256, Vec,
    crypto::bn254::{Bn254G1Affine as G1Affine, Bn254G2Affine as G2Affine},
    testutils::Address as _,
    token::{Client as TokenClient, StellarAssetClient},
    xdr::ToXdr,
};
use soroban_utils::{constants::bn256_modulus, utils::MockToken};

/// Number of levels for the ASP Membership Merkle tree in tests
const ASP_MEMBERSHIP_LEVELS: u32 = 8;

// Helper to get 32 bytes
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

fn register_mock_token(env: &Env) -> Address {
    env.register(MockToken, ())
}

/// A real asset contract with `holder` funded. `MockToken` reports zero for
/// everyone and moves nothing, so a balance assertion against it would pass
/// whatever the pool did.
fn register_funded_token(env: &Env, holder: &Address, amount: i128) -> Address {
    let token = env.register_stellar_asset_contract_v2(Address::generate(env));
    let address = token.address();
    StellarAssetClient::new(env, &address).mint(holder, &amount);
    address
}

/// Create a mock Groth16 proof for testing
///
/// This creates a dummy proof with valid curve points.
/// The actual proof validity is not checked in unit tests for now
fn mk_mock_groth16_proof(env: &Env) -> Groth16Proof {
    // G1 generator point
    let g1_bytes = {
        let mut bytes = [0u8; 64];
        bytes[31] = 1; // x = 1 (big-endian)
        bytes[63] = 2; // y = 2 (big-endian)
        bytes
    };

    // G2 generator point
    let g2_bytes = {
        let mut bytes = [0u8; 128];
        // Set some non-zero values for a valid-looking G2 point
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

/// Creates and deploys all contracts needed for testing
fn setup_test_contracts(env: &Env) -> TestSetup {
    let admin = Address::generate(env);

    // Register ASP Membership contract
    let asp_membership_address =
        env.register(ASPMembership, (admin.clone(), ASP_MEMBERSHIP_LEVELS));
    let asp_membership_client = ASPMembershipClient::new(env, &asp_membership_address);

    // Register ASP Non-Membership contract
    let asp_non_membership_address = env.register(ASPNonMembership, (admin.clone(),));
    let asp_non_membership_client = ASPNonMembershipClient::new(env, &asp_non_membership_address);

    // Register CircomGroth16Verifier contract
    let verifier_address = env.register(CircomGroth16Verifier, ());

    TestSetup {
        admin,
        token: register_mock_token(env),
        verifier: verifier_address,
        asp_membership_address,
        asp_non_membership_address,
        asp_membership_client,
        asp_non_membership_client,
    }
}

fn register_pool(
    env: &Env,
    setup: &TestSetup,
    maximum_deposit_amount: U256,
    levels: u32,
    policy_flags: u32,
) -> Address {
    env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            maximum_deposit_amount,
            levels,
            policy_flags,
        ),
    )
}

fn asp_roots(setup: &TestSetup) -> (U256, U256) {
    (
        setup.asp_membership_client.get_root(),
        setup.asp_non_membership_client.get_root(),
    )
}

/// Baseline transact proof with valid pool root, ext hash, and public amount.
fn mk_transact_proof(
    env: &Env,
    pool: &PoolContractClient,
    asp_membership_root: U256,
    asp_non_membership_root: U256,
    nullifier: u32,
) -> (Proof, ExtData) {
    let root = pool.get_root();
    let ext = mk_ext_data(env, Address::generate(env), 0);
    let ext_hash = compute_ext_hash(env, &ext);
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
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, flags);
    let pool = PoolContractClient::new(&env, &pool_id);
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
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, flags);
    let pool = PoolContractClient::new(&env, &pool_id);
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
    );

    assert!(
        !matches!(
            pool.try_transact(&proof, &ext, &sender),
            Err(Ok(Error::NonCanonicalPublicInput))
        ),
        "expected ASP root field to be skipped for flags={}",
        flags
    );
}

/// Create a test environment that disables snapshot writing under Miri.
/// Miri's isolation mode blocks filesystem operations, which the Soroban SDK
/// uses for test snapshots.
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

#[test]
fn pool_constructor_sets_state() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max.clone(),
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    let stored_admin: Address = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&crate::pool::DataKey::Admin)
            .unwrap_or_else(|| panic!("expected admin to be stored"))
    });
    let stored_max: U256 = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&crate::pool::DataKey::MaximumDepositAmount)
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
    let _root = pool.get_root();
}

#[test]
#[cfg_attr(miri, ignore)]
fn merkle_init_only_once() {
    let env = test_env();
    // As MerkleTreeWithHistory is now a module
    // We need to register the contract first to access the env.storage of a
    // smart contract
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    // First init should succeed
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );

    env.as_contract(&pool_id, || {
        // Second init should return AlreadyInitialized error
        let result = MerkleTreeWithHistory::init(&env, levels);
        assert!(result.is_err());
    });
}

#[test]
fn merkle_insert_updates_root_and_index() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );

    env.as_contract(&pool_id, || {
        let leaf1 = U256::from_u32(&env, 0x01);
        let leaf2 = U256::from_u32(&env, 0x02);

        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(&env, leaf1, leaf2)
            .unwrap_or_else(|err| panic!("expected leaf insertion to succeed: {err:?}"));
        assert_eq!(idx_0, 0);
        assert_eq!(idx_1, 1);

        // last root must be known
        let root = MerkleTreeWithHistory::get_last_root(&env)
            .unwrap_or_else(|err| panic!("expected last root to exist: {err:?}"));
        assert!(
            MerkleTreeWithHistory::is_known_root(&env, &root)
                .unwrap_or_else(|err| panic!("expected root lookup to succeed: {err:?}"))
        );

        // nextIndex should now be 2 (stored in persistent storage)
        let next: u64 = env
            .storage()
            .persistent()
            .get(&MerkleDataKey::NextIndex)
            .unwrap_or_else(|| panic!("expected next index to be stored"));
        assert_eq!(next, 2);
    });
}

#[test]
fn pool_is_known_root_returns_true_for_latest_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        8,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    let latest_root = pool.get_root();

    assert!(pool.is_known_root(&latest_root));
}

#[test]
fn pool_is_known_root_returns_true_for_recent_historical_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        8,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::insert_two_leaves(
            &env,
            U256::from_u32(&env, 1),
            U256::from_u32(&env, 2),
        )
        .unwrap_or_else(|err| panic!("expected first insertion to succeed: {err:?}"));
    });
    let historical_root = pool.get_root();
    env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::insert_two_leaves(
            &env,
            U256::from_u32(&env, 3),
            U256::from_u32(&env, 4),
        )
        .unwrap_or_else(|err| panic!("expected second insertion to succeed: {err:?}"));
    });

    assert!(pool.is_known_root(&historical_root));
}

#[test]
fn pool_is_known_root_returns_false_for_zero_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        8,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);
    let zero_root = U256::from_u32(&env, 0);

    assert!(!pool.is_known_root(&zero_root));
}

#[cfg_attr(
    miri,
    ignore = "too slow under Miri: 90 Merkle insertions exceed the 6h job limit"
)]
#[test]
fn pool_is_known_root_returns_false_for_evicted_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        8,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::insert_two_leaves(
            &env,
            U256::from_u32(&env, 1),
            U256::from_u32(&env, 2),
        )
        .unwrap_or_else(|err| panic!("expected first insertion to succeed: {err:?}"));
    });
    let evicted_root = pool.get_root();

    for i in 0..90u32 {
        let left = i
            .checked_mul(2)
            .and_then(|value| value.checked_add(3))
            .unwrap_or_else(|| panic!("left leaf value overflow"));
        let right = left
            .checked_add(1)
            .unwrap_or_else(|| panic!("right leaf value overflow"));
        env.as_contract(&pool_id, || {
            MerkleTreeWithHistory::insert_two_leaves(
                &env,
                U256::from_u32(&env, left),
                U256::from_u32(&env, right),
            )
            .unwrap_or_else(|err| {
                panic!("expected history rotation insertion to succeed: {err:?}")
            });
        });
    }

    assert!(!pool.is_known_root(&evicted_root));
}

#[test]
fn merkle_insert_fails_when_full() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 1u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );

    env.as_contract(&pool_id, || {
        let leaf1 = U256::from_u32(&env, 0x0A);
        let leaf2 = U256::from_u32(&env, 0x0B);

        // First insert should succeed
        let result1 = MerkleTreeWithHistory::insert_two_leaves(&env, leaf1.clone(), leaf2.clone());
        assert!(result1.is_ok());

        // Second insert should fail with MerkleTreeFull error
        let result2 = MerkleTreeWithHistory::insert_two_leaves(&env, leaf1, leaf2);
        assert!(result2.is_err());
    });
}

#[test]
#[cfg_attr(miri, ignore)]
fn merkle_init_rejects_zero_levels() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let levels = 0u32;

    env.as_contract(&pool_id, || {
        let result = MerkleTreeWithHistory::init(&env, levels);
        assert!(result.is_err());
    });
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_unknown_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let root = U256::from_u32(&env, 0xFF); // not a known root
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let ext = mk_ext_data(&env, Address::generate(&env), 0);

    // Get actual roots
    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
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
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_bad_ext_hash() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);

    // Get actual roots
    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

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
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_bad_public_amount() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = register_pool(
        &env,
        &setup,
        max,
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    // Get actual roots
    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

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
        public_amount: U256::from_u32(&env, 1), // should be 0 for ext_amount=0, fee=0
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
    };

    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_non_canonical_nullifier() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let maximum_deposit_amount = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = register_pool(
        &env,
        &setup,
        maximum_deposit_amount.clone(),
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            let non_canonical_nullifier = bn256_modulus(&env);
            v.push_back(non_canonical_nullifier);
            v
        },
        output_commitment0: U256::from_u32(&env, 0x07),
        output_commitment1: U256::from_u32(&env, 0x08),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
    };

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
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
#[cfg_attr(miri, ignore)]
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
fn get_policy_flags_returns_registered_value() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let flag_sets = [
        0u32,
        policy::ALLOWLIST_BIT,
        policy::BLOCKLIST_BIT,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    ];

    for flags in flag_sets {
        let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, flags);
        let pool = PoolContractClient::new(&env, &pool_id);
        assert_eq!(pool.get_policy_flags(), flags);
    }
}

#[test]
fn get_policy_flags_errors_when_unset() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0u32);
    let pool = PoolContractClient::new(&env, &pool_id);

    env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .remove(&crate::pool::DataKey::PolicyFlags);
    });

    assert!(matches!(
        pool.try_get_policy_flags(),
        Err(Ok(Error::NotInitialized))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_errors_when_policy_flags_unset() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .remove(&crate::pool::DataKey::PolicyFlags);
    });

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let (member_root, non_member_root) = asp_roots(&setup);
    let (proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xB8);

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NotInitialized))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_non_canonical_output_commitment() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let maximum_deposit_amount = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = register_pool(
        &env,
        &setup,
        maximum_deposit_amount.clone(),
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

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
    };

    assert!(matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn transact_does_not_reject_boundary_canonical_public_input() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let maximum_deposit_amount = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = register_pool(
        &env,
        &setup,
        maximum_deposit_amount.clone(),
        levels,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();
    let one = U256::from_u32(&env, 1);

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            let canonical_boundary_nullifier = bn256_modulus(&env).sub(&one);
            v.push_back(canonical_boundary_nullifier);
            v
        },
        output_commitment0: bn256_modulus(&env).sub(&one),
        output_commitment1: U256::from_u32(&env, 0x08),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
    };

    assert!(!matches!(
        pool.try_transact(&proof, &ext, &sender),
        Err(Ok(Error::NonCanonicalPublicInput))
    ));
}

#[test]
fn is_spent_false_for_unseen_nullifier() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);
    let nullifier = U256::from_u32(&env, 0xB1);

    assert!(!pool.is_spent(&nullifier));
}

#[test]
fn is_spent_true_after_nullifier_marked() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);
    let spent = U256::from_u32(&env, 0xA1);
    let other = U256::from_u32(&env, 0xA2);

    assert!(!pool.is_spent(&spent));
    assert!(!pool.is_spent(&other));

    // mark spent
    env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .set(&crate::pool::DataKey::Nullifier(spent.clone()), &());
    });

    assert!(pool.is_spent(&spent));
    assert!(!pool.is_spent(&other));

    // indempotency check
    env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .set(&crate::pool::DataKey::Nullifier(spent.clone()), &());
    });
    assert!(pool.is_spent(&spent));
}

#[test]
fn test_pool_events_exact_shapes() {
    use crate::pool::{NewCommitmentEvent, NewNullifierEvent};
    use soroban_sdk::{events::Event, testutils::Events};
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let contract_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let commitment = U256::from_u32(&env, 123);
    let nullifier = U256::from_u32(&env, 456);
    let encrypted_output = Bytes::from_array(&env, &[0u8; 120]);

    env.as_contract(&contract_id, || {
        let event1 = NewCommitmentEvent {
            commitment: commitment.clone(),
            index: 0,
            encrypted_output: encrypted_output.clone(),
        };
        event1.publish(&env);

        let event2 = NewNullifierEvent {
            nullifier: nullifier.clone(),
        };
        event2.publish(&env);
    });

    let events = env.events().all();
    assert_eq!(events.events().len(), 2);

    let expected_commitment = NewCommitmentEvent {
        commitment,
        index: 0,
        encrypted_output,
    }
    .to_xdr(&env, &contract_id);
    assert_eq!(events.events()[0], expected_commitment);

    let expected_nullifier = NewNullifierEvent { nullifier }.to_xdr(&env, &contract_id);
    assert_eq!(events.events()[1], expected_nullifier);
}

/// Marks a nullifier as spent directly in pool storage, mirroring what a
/// successful `transact` does in step 6. Used to reach the replay path without
/// needing a real Groth16 proof for the first spend.
fn mark_nullifier_spent(env: &Env, pool_id: &Address, nullifier: &U256) {
    env.as_contract(pool_id, || {
        env.storage()
            .persistent()
            .set(&crate::pool::DataKey::Nullifier(nullifier.clone()), &());
    });
}

/// Replay: a nullifier that is already spent must be refused, and refused for
/// that reason rather than falling through to proof verification.
#[test]
fn transact_rejects_replay_of_spent_nullifier() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let nullifier = 0xC0FFEE;
    mark_nullifier_spent(&env, &pool_id, &U256::from_u32(&env, nullifier));

    let (proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, nullifier);
    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("spent nullifier must be refused");
    assert_eq!(err, Ok(Error::AlreadySpentNullifier));
}

/// A deposit above the configured maximum is refused before any token moves,
/// so the check cannot be bypassed by an unfunded sender.
#[test]
fn transact_rejects_deposit_above_maximum() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = 1000u32;
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, max), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let (proof, _) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xD1);
    // try_from rather than `as`: the boundary is the whole point of this test,
    // so a value that did not fit i32 must fail loudly instead of wrapping
    // into a negative deposit.
    let above_max = i32::try_from(max + 1).expect("max + 1 must fit i32");
    let over = mk_ext_data(&env, Address::generate(&env), above_max);

    let err = pool
        .try_transact(&proof, &over, &Address::generate(&env))
        .expect_err("deposit above the maximum must be refused");
    assert_eq!(err, Ok(Error::WrongExtAmount));
}

/// A deposit exactly at the maximum is not rejected by the bound itself. It
/// still fails later on the mock proof, which is what pins the boundary as
/// inclusive rather than off by one.
#[test]
fn transact_accepts_deposit_at_maximum_bound() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let max = 1000u32;
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, max), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let (proof, _) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xD2);
    let at_max = i32::try_from(max).expect("max must fit i32");
    let at = mk_ext_data(&env, Address::generate(&env), at_max);

    let err = pool
        .try_transact(&proof, &at, &Address::generate(&env))
        .expect_err("the mock proof still fails verification");
    assert_ne!(
        err,
        Ok(Error::WrongExtAmount),
        "a deposit equal to the maximum must not be rejected by the bound"
    );
}

/// An all-zero proof must be refused with a clean error rather than panicking.
///
/// The points are all-zero but not empty, so the `is_empty` guard does not
/// catch them and the proof reaches the verifier, which refuses it. The caller
/// sees `InvalidProof`, the pool's own error, rather than whichever
/// `Groth16Error` the verifier happened to raise.
#[test]
fn transact_rejects_zeroed_proof() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let (mut proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE1);
    proof.proof = Groth16Proof {
        a: G1Affine::from_array(&env, &[0u8; 64]),
        b: G2Affine::from_array(&env, &[0u8; 128]),
        c: G1Affine::from_array(&env, &[0u8; 64]),
    };

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("a zeroed proof must be refused");
    assert_eq!(
        err,
        Ok(Error::InvalidProof),
        "a proof the verifier refuses must be reported as InvalidProof"
    );
}

/// The spent-check only compares each nullifier against stored state, so a
/// duplicate inside one call passes it and is left to the circuit, which
/// constrains pairwise distinctness.
#[test]
#[cfg_attr(
    miri,
    ignore = "Stacked Borrows UB in the host error path, not in this contract"
)]
fn transact_leaves_duplicate_nullifier_detection_to_the_circuit() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(
        &env,
        &setup,
        U256::from_u32(&env, 1000),
        3,
        policy::ALLOWLIST_BIT | policy::BLOCKLIST_BIT,
    );
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let dup = U256::from_u32(&env, 0xDEAD);
    let (mut proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xDEAD);
    proof.input_nullifiers.push_back(dup);

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("the mock proof fails verification");
    assert_ne!(
        err,
        Ok(Error::AlreadySpentNullifier),
        "the spent-check compares each nullifier against stored state only, so a \
         duplicate inside one call passes it and is left to the circuit"
    );
}

/// Number of root history slots the pool keeps. Rotating this many times
/// evicts a root that was valid when it was recorded.
const ROOT_HISTORY_SIZE: u32 = 90;

/// Inserts two leaves through the pool's Merkle module, rotating the root
/// history by one slot. Used to age a root out of history without needing a
/// real proof for each intermediate transaction.
fn rotate_root(env: &Env, pool_id: &Address, left: u32, right: u32) {
    env.as_contract(pool_id, || {
        MerkleTreeWithHistory::insert_two_leaves(
            env,
            U256::from_u32(env, left),
            U256::from_u32(env, right),
        )
        .unwrap_or_else(|err| panic!("expected root rotation to succeed: {err:?}"));
    });
}

/// A root the pool has never recorded must be refused as `UnknownRoot`.
/// Everything else in the proof is well formed, so the root is the only reason
/// left to refuse.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_root_never_inserted() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let (mut proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE1);
    proof.root = U256::from_u32(&env, 0xFF);

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("a root the pool never recorded must be refused");
    assert_eq!(err, Ok(Error::UnknownRoot));
}

/// A root pushed out of the history ring must be refused too. This is the
/// stale-proof case: built against real pool state, arriving too late.
#[test]
#[cfg_attr(
    miri,
    ignore = "too slow under Miri: 90 Merkle insertions exceed the 6h job limit"
)]
fn transact_rejects_evicted_root() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 8, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    rotate_root(&env, &pool_id, 1, 2);
    let evicted_root = pool.get_root();
    assert!(
        pool.is_known_root(&evicted_root),
        "the root must start out known, otherwise this test proves nothing"
    );

    for i in 0..ROOT_HISTORY_SIZE {
        let left = i
            .checked_mul(2)
            .and_then(|value| value.checked_add(3))
            .unwrap_or_else(|| panic!("left leaf value overflow"));
        let right = left
            .checked_add(1)
            .unwrap_or_else(|| panic!("right leaf value overflow"));
        rotate_root(&env, &pool_id, left, right);
    }

    let (mut proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE2);
    proof.root = evicted_root;

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("a root evicted from history must be refused");
    assert_eq!(err, Ok(Error::UnknownRoot));
}

/// The root check runs first, so a transaction wrong in all three ways is
/// reported as `UnknownRoot`. The caller only ever sees the first failure.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_reports_unknown_root_before_later_checks() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let nullifier = 0xE3;
    // Presence of the key is the spent flag, the same shape `mark_spent`
    // writes.
    env.as_contract(&pool_id, || {
        env.storage().persistent().set(
            &crate::pool::DataKey::Nullifier(U256::from_u32(&env, nullifier)),
            &(),
        );
    });

    let (mut proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, nullifier);
    proof.root = U256::from_u32(&env, 0xFF);
    proof.ext_data_hash = mk_bytesn32(&env, 0x99);

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("an unknown root must be refused whatever else is wrong");
    assert_eq!(err, Ok(Error::UnknownRoot));
}

/// The deposit branch is strictly greater than zero, so `ext_amount == 0`
/// skips the maximum-deposit bound even when that maximum is zero, and the
/// transaction is refused only by the verifier.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_accepts_zero_ext_amount_with_zero_maximum_deposit() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 0), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    env.mock_all_auths();

    let (proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE4);
    assert_eq!(ext.ext_amount, I256::from_i32(&env, 0));

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("the mock proof still fails verification");
    assert_ne!(
        err,
        Ok(Error::WrongExtAmount),
        "a zero-value transaction must not be treated as a deposit"
    );
    assert_eq!(err, Ok(Error::InvalidProof));
}

/// A verifier rejection must reach the caller as the pool's own `InvalidProof`.
/// The two enums are both `#[repr(u32)]` and their codes collide, so an
/// untrapped rejection used to surface as `NotAuthorized`.
#[test]
fn transact_reports_verifier_rejection_as_invalid_proof() {
    let env = test_env();
    let setup = setup_test_contracts(&env);
    // Policy flags 0: neither ASP root is compared, so neither can produce the
    // InvalidProof this test asserts.
    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);
    // Authorization is mocked, so NotAuthorized cannot be a genuine answer.
    env.mock_all_auths();

    let (proof, ext) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE5);
    assert!(
        !proof.proof.is_empty(),
        "the proof must be non-empty, otherwise the empty-proof guard answers instead of the verifier"
    );

    let err = pool
        .try_transact(&proof, &ext, &Address::generate(&env))
        .expect_err("a proof the verifier refuses must be refused by the pool");
    assert_eq!(
        err,
        Ok(Error::InvalidProof),
        "a verifier rejection must be reported as the pool's InvalidProof, not as the \
         NotAuthorized that Groth16Error::MalformedPublicInputs shares a code with"
    );
}

/// A deposit whose proof the verifier refuses must revert whole. `transact`
/// moves the tokens before `internal_transact` checks anything, so the sender
/// keeps their balance only if the failed call is rolled back.
#[test]
#[cfg_attr(miri, ignore)]
fn transact_rejects_deposit_with_invalid_proof_without_moving_funds() {
    let env = test_env();
    let mut setup = setup_test_contracts(&env);
    env.mock_all_auths();

    let sender = Address::generate(&env);
    let funded = 10_000i128;
    setup.token = register_funded_token(&env, &sender, funded);
    let token = TokenClient::new(&env, &setup.token);

    let pool_id = register_pool(&env, &setup, U256::from_u32(&env, 1000), 3, 0);
    let pool = PoolContractClient::new(&env, &pool_id);
    let (member_root, non_member_root) = asp_roots(&setup);

    let deposit_amount = 500u32;
    let deposit = mk_ext_data(
        &env,
        Address::generate(&env),
        i32::try_from(deposit_amount).expect("the deposit must fit i32"),
    );
    let (mut proof, _) = mk_transact_proof(&env, &pool, member_root, non_member_root, 0xE6);
    // Everything before verification must pass, or the revert being asserted
    // would be an earlier check rather than the verifier.
    proof.ext_data_hash = compute_ext_hash(&env, &deposit);
    proof.public_amount = U256::from_u32(&env, deposit_amount);

    assert_eq!(token.balance(&sender), funded);
    assert_eq!(token.balance(&pool_id), 0);

    let err = pool
        .try_transact(&proof, &deposit, &sender)
        .expect_err("a deposit carrying a proof the verifier refuses must be refused");
    assert_eq!(
        err,
        Ok(Error::InvalidProof),
        "the deposit bound must not answer first, or the transfer is never reached"
    );
    assert_eq!(
        token.balance(&sender),
        funded,
        "a refused deposit must not debit the sender"
    );
    assert_eq!(
        token.balance(&pool_id),
        0,
        "a refused deposit must not credit the pool"
    );
}
