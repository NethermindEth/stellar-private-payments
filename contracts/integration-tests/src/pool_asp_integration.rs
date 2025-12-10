//! Integration tests for Pool <-> ASP contracts interaction
//!
//! These tests verify cross-contract interactions between the Pool contract
//! and the ASP Membership/Non-Membership contracts.

use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use pool::{ExtData, PoolContract, PoolContractClient, Proof};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{Address, Bytes, BytesN, Env, I256, U256, Vec};
use soroban_utils::constants::bn256_modulus;
use soroban_utils::utils::MockToken;

// Test constants
/// Number of levels for the Pool commitment Merkle tree
const POOL_MERKLE_LEVELS: u32 = 8;
/// Number of levels for the ASP Membership Merkle tree
const ASP_MEMBERSHIP_LEVELS: u32 = 8;
/// Maximum deposit amount for the pool
const MAX_DEPOSIT: u32 = 1_000_000;

// Test Environment Setup
/// Complete test environment with all deployed contracts
struct IntegrationTestEnv<'a> {
    env: Env,
    pool_address: Address,
    asp_admin: Address,
    pool_client: PoolContractClient<'a>,
    asp_membership_client: ASPMembershipClient<'a>,
    asp_non_membership_client: ASPNonMembershipClient<'a>,
}

impl<'a> IntegrationTestEnv<'a> {
    /// Deploy and initialize all contracts for integration testing
    fn setup(env: &Env) -> IntegrationTestEnv<'a> {
        // Generate admin addresses
        let pool_admin = Address::generate(env);
        let asp_admin = Address::generate(env); // For testing purposes we use the same address for both contracts

        // Deploy mock token
        let token_address = env.register(MockToken, ());

        // Deploy mock verifier (just an address for now)
        // TODO: Update when verifier is ready
        let verifier_address = Address::generate(env);

        // Deploy and initialize ASP Membership contract
        let asp_membership_address = env.register(ASPMembership, ());
        let asp_membership_client = ASPMembershipClient::new(env, &asp_membership_address);
        asp_membership_client.init(&asp_admin, &ASP_MEMBERSHIP_LEVELS);

        // Deploy and initialize ASP Non-Membership contract
        let asp_non_membership_address = env.register(ASPNonMembership, ());
        let asp_non_membership_client =
            ASPNonMembershipClient::new(env, &asp_non_membership_address);
        asp_non_membership_client.init(&asp_admin);

        // Deploy and initialize Pool contract
        let pool_address = env.register(PoolContract, ());
        let pool_client = PoolContractClient::new(env, &pool_address);
        let max_deposit = U256::from_u32(env, MAX_DEPOSIT);
        pool_client.init(
            &pool_admin,
            &token_address,
            &verifier_address,
            &asp_membership_address,
            &asp_non_membership_address,
            &max_deposit,
            &POOL_MERKLE_LEVELS,
        );

        IntegrationTestEnv {
            env: env.clone(),
            pool_address,
            asp_admin,
            pool_client,
            asp_membership_client,
            asp_non_membership_client,
        }
    }

    /// Get current roots from both ASP contracts
    fn get_asp_roots(&self) -> (U256, U256) {
        let membership_root = self.asp_membership_client.get_root();
        let non_membership_root = self.asp_non_membership_client.get_root();
        (membership_root, non_membership_root)
    }

    /// Create external data for a transaction
    fn create_ext_data(&self, recipient: &Address, ext_amount: i32, fee: u32) -> ExtData {
        ExtData {
            recipient: recipient.clone(),
            ext_amount: I256::from_i32(&self.env, ext_amount),
            fee: U256::from_u32(&self.env, fee),
            encrypted_output0: Bytes::new(&self.env),
            encrypted_output1: Bytes::new(&self.env),
        }
    }

    /// Compute the hash of external data
    fn compute_ext_hash(&self, ext: &ExtData) -> BytesN<32> {
        let payload = ext.clone().to_xdr(&self.env);
        let digest: BytesN<32> = self.env.crypto().keccak256(&payload).into();
        let digest_u256 = U256::from_be_bytes(&self.env, &Bytes::from(digest));
        let reduced = digest_u256.rem_euclid(&bn256_modulus(&self.env));
        let mut buf = [0u8; 32];
        reduced.to_be_bytes().copy_into_slice(&mut buf);
        BytesN::from_array(&self.env, &buf)
    }
}

// Integration Tests
// Contract Deployment and Initialization
// For now we use bogus values for the verification. TODO: Will be updated when verifier is ready.
#[test]
fn test_all_contracts_deploy_and_initialize() {
    let env = Env::default();
    let test_env = IntegrationTestEnv::setup(&env);

    // Verify ASP Membership contract is initialized and has a root
    let membership_root = test_env.asp_membership_client.get_root();
    // After initialization, the root should be different from 0 (as we define zero differently for each level)
    assert_ne!(membership_root, U256::from_u32(&env, 0));

    // Verify ASP Non-Membership contract is initialized (root starts at 0 for empty SMT)
    let non_membership_root = test_env.asp_non_membership_client.get_root();
    assert_eq!(non_membership_root, U256::from_u32(&env, 0));
}

#[test]
fn test_pool_reads_asp_roots_via_cross_contract_call() {
    let env = Env::default();
    let test_env = IntegrationTestEnv::setup(&env);

    // Get roots directly from ASP contracts
    let (direct_membership_root, direct_non_membership_root) = test_env.get_asp_roots();

    // Get roots via Pool's cross-contract call
    let pool_membership_root = test_env.pool_client.get_asp_membership_root();
    let pool_non_membership_root = test_env.pool_client.get_asp_non_membership_root();

    // Verify they match
    assert_eq!(direct_membership_root, pool_membership_root);
    assert_eq!(direct_non_membership_root, pool_non_membership_root);
}

#[test]
fn test_pool_reflects_asp_membership_root_changes() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    // Get initial root
    let initial_root = test_env.pool_client.get_asp_membership_root();

    // Add a leaf to ASP Membership (this changes the root)
    let leaf = U256::from_u32(&env, 0x12345678);
    test_env.asp_membership_client.insert_leaf(&leaf);

    // Get new root via Pool
    let new_root = test_env.pool_client.get_asp_membership_root();

    // Root should have changed
    assert_ne!(initial_root, new_root);

    // Verify it matches direct call
    let direct_root = test_env.asp_membership_client.get_root();
    assert_eq!(new_root, direct_root);
}

#[test]
fn test_pool_reflects_asp_non_membership_root_changes() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    // Get initial root (should be 0 for empty SMT)
    let initial_root = test_env.pool_client.get_asp_non_membership_root();
    assert_eq!(initial_root, U256::from_u32(&env, 0));

    // Add a leaf to ASP Non-Membership (this changes the root)
    let key = U256::from_u32(&env, 0xABCDEF);
    let value = U256::from_u32(&env, 0x123456);
    test_env.asp_non_membership_client.insert_leaf(&key, &value);

    // Get new root via Pool
    let new_root = test_env.pool_client.get_asp_non_membership_root();

    // Root should have changed from 0
    assert_ne!(initial_root, new_root);

    // Verify it matches direct call
    let direct_root = test_env.asp_non_membership_client.get_root();
    assert_eq!(new_root, direct_root);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // InvalidProof error
fn test_transact_fails_with_wrong_asp_membership_root() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Get current ASP roots
    let (_, asp_non_membership_root) = test_env.get_asp_roots();

    // Use WRONG membership root
    let wrong_membership_root = U256::from_u32(&env, 0xDEADBEEF);

    // Get pool's Merkle root
    let pool_root = env.as_contract(&test_env.pool_address, || {
        pool::merkle_with_history::MerkleTreeWithHistory::get_last_root(&env)
    });

    let ext_data = test_env.create_ext_data(&recipient, 0, 0);
    let ext_hash = test_env.compute_ext_hash(&ext_data);

    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: pool_root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0x4444));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x5555),
        output_commitment1: U256::from_u32(&env, 0x6666),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root: wrong_membership_root,
        asp_non_membership_root,
    };

    // Transaction should fail with InvalidProof
    test_env.pool_client.transact(&proof, &ext_data, &sender);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // InvalidProof error
fn test_transact_fails_with_wrong_asp_non_membership_root() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Get current ASP roots
    let (asp_membership_root, _) = test_env.get_asp_roots();

    // Use WRONG non-membership root
    let wrong_non_membership_root = U256::from_u32(&env, 0xCAFEBABE);

    // Get pool's Merkle root
    let pool_root = env.as_contract(&test_env.pool_address, || {
        pool::merkle_with_history::MerkleTreeWithHistory::get_last_root(&env)
    });

    let ext_data = test_env.create_ext_data(&recipient, 0, 0);
    let ext_hash = test_env.compute_ext_hash(&ext_data);

    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: pool_root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0x7777));
            v
        },
        output_commitment0: U256::from_u32(&env, 0x8888),
        output_commitment1: U256::from_u32(&env, 0x9999),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root,
        asp_non_membership_root: wrong_non_membership_root,
    };

    // Transaction should fail with InvalidProof
    test_env.pool_client.transact(&proof, &ext_data, &sender);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")] // InvalidProof error
fn test_transact_fails_with_stale_asp_roots() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);

    // Get initial ASP roots
    let (old_membership_root, old_non_membership_root) = test_env.get_asp_roots();

    // Update ASP Membership (add a leaf to change the root)
    let leaf = U256::from_u32(&env, 0xFEDCBA98);
    test_env.asp_membership_client.insert_leaf(&leaf);

    // Get pool's Merkle root
    let pool_root = env.as_contract(&test_env.pool_address, || {
        pool::merkle_with_history::MerkleTreeWithHistory::get_last_root(&env)
    });

    let ext_data = test_env.create_ext_data(&recipient, 0, 0);
    let ext_hash = test_env.compute_ext_hash(&ext_data);

    // Use OLD (stale) membership root
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: pool_root,
        input_nullifiers: {
            let mut v: Vec<U256> = Vec::new(&env);
            v.push_back(U256::from_u32(&env, 0xAAAA));
            v
        },
        output_commitment0: U256::from_u32(&env, 0xBBBB),
        output_commitment1: U256::from_u32(&env, 0xCCCC),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
        asp_membership_root: old_membership_root,
        asp_non_membership_root: old_non_membership_root,
    };

    // Transaction should fail because ASP membership root has changed
    test_env.pool_client.transact(&proof, &ext_data, &sender);
}

#[test]
fn test_admin_can_update_asp_membership_address() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    // Deploy a new ASP Membership contract
    let new_asp_membership_address = env.register(ASPMembership, ());
    let new_asp_membership_client = ASPMembershipClient::new(&env, &new_asp_membership_address);
    new_asp_membership_client.init(&test_env.asp_admin, &ASP_MEMBERSHIP_LEVELS);

    // Add a leaf to new contract so it has a different root
    let leaf = U256::from_u32(&env, 0x11111111);
    new_asp_membership_client.insert_leaf(&leaf);

    // Get the root from the new contract
    let new_root = new_asp_membership_client.get_root();

    // Update pool to use new ASP Membership contract
    test_env
        .pool_client
        .update_asp_membership(&new_asp_membership_address);

    // Verify pool now reads from new contract
    let pool_root = test_env.pool_client.get_asp_membership_root();
    assert_eq!(pool_root, new_root);
}

#[test]
fn test_admin_can_update_asp_non_membership_address() {
    let env = Env::default();
    env.mock_all_auths();

    let test_env = IntegrationTestEnv::setup(&env);

    // Deploy a new ASP Non-Membership contract
    let new_asp_non_membership_address = env.register(ASPNonMembership, ());
    let new_asp_non_membership_client =
        ASPNonMembershipClient::new(&env, &new_asp_non_membership_address);
    new_asp_non_membership_client.init(&test_env.asp_admin);

    // Add a leaf to new contract so it has a different root
    let key = U256::from_u32(&env, 0x22222222);
    let value = U256::from_u32(&env, 0x33333333);
    new_asp_non_membership_client.insert_leaf(&key, &value);

    // Get the root from the new contract
    let new_root = new_asp_non_membership_client.get_root();

    // Update pool to use new ASP Non-Membership contract
    test_env
        .pool_client
        .update_asp_non_membership(&new_asp_non_membership_address);

    // Verify pool now reads from new contract
    let pool_root = test_env.pool_client.get_asp_non_membership_root();
    assert_eq!(pool_root, new_root);
}
