use crate::merkle_with_history::{MerkleDataKey, MerkleTreeWithHistory};
use crate::{ExtData, PoolContract, PoolContractClient, Proof};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, Groth16Proof, VerificationKeyBytes};
use soroban_sdk::crypto::bn254::{G1Affine, G2Affine};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, I256, U256, Vec};
use soroban_utils::constants::bn256_modulus;
use soroban_utils::utils::MockToken;

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

fn dummy_vk_bytes(env: &Env) -> VerificationKeyBytes {
    let alpha = BytesN::from_array(env, &[0u8; 64]);
    let beta = BytesN::from_array(env, &[0u8; 128]);
    let gamma = BytesN::from_array(env, &[0u8; 128]);
    let delta = BytesN::from_array(env, &[0u8; 128]);
    let mut ic = Vec::new(env);
    for _ in 0..12 {
        ic.push_back(BytesN::from_array(env, &[0u8; 64]));
    }
    VerificationKeyBytes {
        alpha,
        beta,
        gamma,
        delta,
        ic,
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
    let verifier_address = env.register(CircomGroth16Verifier, (dummy_vk_bytes(env),));

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

#[test]
fn pool_constructor_sets_state() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
    );
    let pool = PoolContractClient::new(&env, &pool_id);

    let stored_admin: Address = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&crate::pool::DataKey::Admin)
            .unwrap()
    });
    let stored_max: U256 = env.as_contract(&pool_id, || {
        env.storage()
            .persistent()
            .get(&crate::pool::DataKey::MaximumDepositAmount)
            .unwrap()
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
fn merkle_init_only_once() {
    let env = Env::default();
    // As MerkleTreeWithHistory is now a module
    // We need to register the contract first to access the env.storage of a smart contract
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    // First init should succeed
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
    );

    env.as_contract(&pool_id, || {
        // Second init should return AlreadyInitialized error
        let result = MerkleTreeWithHistory::init(&env, levels);
        assert!(result.is_err());
    });
}

#[test]
fn merkle_insert_updates_root_and_index() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
    );

    env.as_contract(&pool_id, || {
        let leaf1 = U256::from_u32(&env, 0x01);
        let leaf2 = U256::from_u32(&env, 0x02);

        let (idx_0, idx_1) = MerkleTreeWithHistory::insert_two_leaves(&env, leaf1, leaf2).unwrap();
        assert_eq!(idx_0, 0);
        assert_eq!(idx_1, 1);

        // last root must be known
        let root = MerkleTreeWithHistory::get_last_root(&env).unwrap();
        assert!(MerkleTreeWithHistory::is_known_root(&env, &root).unwrap());

        // nextIndex should now be 2 (stored in persistent storage)
        let next: u64 = env
            .storage()
            .persistent()
            .get(&MerkleDataKey::NextIndex)
            .unwrap();
        assert_eq!(next, 2);
    });
}

#[test]
fn merkle_insert_fails_when_full() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 1u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
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
fn merkle_init_rejects_zero_levels() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
    );
    let levels = 0u32;

    env.as_contract(&pool_id, || {
        let result = MerkleTreeWithHistory::init(&env, levels);
        assert!(result.is_err());
    });
}

#[test]
fn transact_rejects_unknown_root() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let root = U256::from_u32(&env, 0xFF); // not a known root
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
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
fn transact_rejects_bad_ext_hash() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
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
fn transact_rejects_bad_public_amount() {
    let env = Env::default();
    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let pool_id = env.register(
        PoolContract,
        (
            setup.admin.clone(),
            setup.token.clone(),
            setup.verifier.clone(),
            setup.asp_membership_address.clone(),
            setup.asp_non_membership_address.clone(),
            max.clone(),
            levels,
        ),
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
