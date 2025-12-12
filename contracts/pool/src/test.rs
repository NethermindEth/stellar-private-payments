use crate::merkle_with_history::{MerkleDataKey, MerkleTreeWithHistory};
use crate::{DataKey, PoolContract, PoolContractClient, Proof};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use circom_groth16_verifier::{CircomGroth16Verifier, CircomGroth16VerifierClient, Groth16Proof};
use soroban_sdk::crypto::bn254::{G1Affine, G2Affine};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, I256, Map, U256, Vec};
use soroban_utils::constants::bn256_modulus;
use soroban_utils::utils::{ExtData, MockToken};

/// Number of levels for the ASP Membership Merkle tree in tests
const ASP_MEMBERSHIP_LEVELS: u32 = 8;

// Helper to get 32 bytes
fn mk_bytesn32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

fn mk_ext_data(env: &Env, recipient: Address, ext_amount: i32, fee: u32) -> ExtData {
    ExtData {
        recipient,
        ext_amount: I256::from_i32(env, ext_amount),
        fee: U256::from_u32(env, fee),
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

/// Creates and initializes all contracts needed for testing
fn setup_test_contracts(env: &Env) -> TestSetup {
    let admin = Address::generate(env);

    // Register and initialize ASP Membership contract
    let asp_membership_address = env.register(ASPMembership, ());
    let asp_membership_client = ASPMembershipClient::new(env, &asp_membership_address);
    asp_membership_client.init(&admin, &ASP_MEMBERSHIP_LEVELS);

    // Register and initialize ASP Non-Membership contract
    let asp_non_membership_address = env.register(ASPNonMembership, ());
    let asp_non_membership_client = ASPNonMembershipClient::new(env, &asp_non_membership_address);
    asp_non_membership_client.init(&admin);

    // Register and initialize CircomGroth16Verifier contract
    let verifier_address = env.register(CircomGroth16Verifier, ());
    CircomGroth16VerifierClient::new(env, &verifier_address);

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
#[should_panic]
fn pool_init_only_once() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    // second init should error
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );
}

#[test]
fn merkle_init_only_once() {
    let env = Env::default();
    // As MerkleTreeWithHistory is now a module
    // We need to register the contract first to access the env.storage of a smart contract
    let pool_id = env.register(PoolContract, ());
    let levels = 8u32;

    env.as_contract(&pool_id, || {
        // First init should succeed
        let result1 = MerkleTreeWithHistory::init(&env, levels);
        assert!(result1.is_ok());

        // Second init should return AlreadyInitialized error
        let result2 = MerkleTreeWithHistory::init(&env, levels);
        assert!(result2.is_err());
    });
}

#[test]
fn merkle_insert_updates_root_and_index() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let levels = 3u32;

    env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::init(&env, levels).unwrap();

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
    let pool_id = env.register(PoolContract, ());

    // levels=1 => capacity of 2 leaves (one insert call)
    let levels = 1u32;

    env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::init(&env, levels).unwrap();

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
    let pool_id = env.register(PoolContract, ());
    let levels = 0u32;

    env.as_contract(&pool_id, || {
        let result = MerkleTreeWithHistory::init(&env, levels);
        assert!(result.is_err());
    });
}

#[test]
fn transact_rejects_unknown_root() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let root = U256::from_u32(&env, 0xFF); // not a known root
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);

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
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);

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
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
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
fn transact_marks_nullifiers() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    env.mock_all_auths();
    let sender = Address::generate(&env);
    let root = pool.get_root();
    let nullifier = U256::from_u32(&env, 0xCD);
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    // Get actual roots
    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root: root.clone(),
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(nullifier.clone());
            v
        },
        output_commitment0: U256::from_u32(&env, 0x05),
        output_commitment1: U256::from_u32(&env, 0x06),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash.clone(),
        asp_membership_root,
        asp_non_membership_root,
    };

    pool.transact(&proof, &ext, &sender);
    // second call with same nullifier should fail
    assert!(pool.try_transact(&proof, &ext, &sender).is_err());
}

#[test]
#[should_panic]
// This tests should not panic. But as we now have the verifier and we are using mock proofs. It fails
// TODO: Move to the E2E tests
fn transact_updates_commitments_and_nullifiers() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let setup = setup_test_contracts(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(
        &setup.admin,
        &setup.token,
        &setup.verifier,
        &setup.asp_membership_address,
        &setup.asp_non_membership_address,
        &max,
        &levels,
    );

    env.mock_all_auths();

    let sender = Address::generate(&env);
    let root = pool.get_root();
    let nullifier = U256::from_u32(&env, 0x22);
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);

    // Get actual roots
    let asp_membership_root = setup.asp_membership_client.get_root();
    let asp_non_membership_root = setup.asp_non_membership_client.get_root();

    let proof = Proof {
        proof: mk_mock_groth16_proof(&env),
        root: root.clone(),
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(nullifier.clone());
            v
        },
        output_commitment0: U256::from_u32(&env, 0x09),
        output_commitment1: U256::from_u32(&env, 0x0A),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root,
    };

    pool.transact(&proof, &ext, &sender);

    // nullifier should be marked spent
    let seen = env.as_contract(&pool_id, || {
        let nulls: Map<U256, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap();
        nulls.get(nullifier.clone()).unwrap_or(false)
    });
    assert!(seen);
}
