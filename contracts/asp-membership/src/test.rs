#![cfg(test)]

use super::*;
use num_bigint::BigUint;
use soroban_sdk::{Address, Bytes, Env, U256, Vec, testutils::Address as _, vec};
use std::ops::AddAssign;
use zkhash::{
    ark_ff::{BigInteger, Fp256, PrimeField},
    fields::bn256::FpBN256 as Scalar,
    poseidon2::poseidon2::Poseidon2,
    poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_2,
};

#[test]
fn test_init_valid() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);

    // Test valid initialization
    ASPMembershipClient::new(&env, &contract_id).init(&admin, &3u32);
}

#[test]
#[should_panic(expected = "Levels must be within the range")]
fn test_init_invalid_levels_zero() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);

    ASPMembershipClient::new(&env, &contract_id).init(&admin, &0u32);
}

#[test]
#[should_panic(expected = "Levels must be within the range [1..32]")]
fn test_init_invalid_levels_too_large() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);

    ASPMembershipClient::new(&env, &contract_id).init(&admin, &33u32);
}

#[test]
fn test_hash_pair() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Test hash_pair with two U256 values
    let left = U256::from_u32(&env, 1u32);
    let right = U256::from_u32(&env, 2u32);

    let result = client.hash_pair(&left, &right);

    // Verify result is a valid U256 (not zero, since we're hashing non-zero values)
    let zero = U256::from_u32(&env, 0u32);
    assert_ne!(result, zero);

    // Test that hash is deterministic
    let result2 = client.hash_pair(&left, &right);
    assert_eq!(result, result2);

    // Test that different inputs produce different hashes
    let left2 = U256::from_u32(&env, 3u32);
    let result3 = client.hash_pair(&left2, &right);
    assert_ne!(result, result3);
}

#[test]
fn test_insert_leaf() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize contract
    client.init(&admin, &3u32);

    // Mock all auths for testing purposes
    env.mock_all_auths();

    // Insert first leaf
    let leaf1 = U256::from_u32(&env, 100u32);
    client.insert_leaf(&admin, &leaf1);

    // Insert the second leaf
    let leaf2 = U256::from_u32(&env, 200u32);
    client.insert_leaf(&admin, &leaf2);

    // Check NextIndex after both insertions
    let next_index1: u32 = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::NextIndex).unwrap()
    });
    assert_eq!(next_index1, 2, "NextIndex should be 2 after two insertions");
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn test_insert_leaf_requires_admin() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let non_admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize contract
    client.init(&admin, &3u32);

    // Try to insert leaf as non-admin
    // It should fail as we did not call mock_all_auths()
    let leaf = U256::from_u32(&env, 100u32);
    client.insert_leaf(&non_admin, &leaf);
}

#[test]
#[should_panic]
fn test_insert_leaf_merkle_tree_full() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize with 2 levels
    client.init(&admin, &2u32);

    // Mock all auths for testing purposes
    env.mock_all_auths();

    // Insert 4 leaves
    for i in 0..4 {
        let leaf = U256::from_u32(&env, (i + 1) as u32);
        client.insert_leaf(&admin, &leaf);
    }

    // Try to insert one more leaf, which should fail as the tree is full
    let leaf5 = U256::from_u32(&env, 5u32);
    client.insert_leaf(&admin, &leaf5);
}

#[test]
fn test_update_admin() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize contract
    client.init(&admin, &3u32);

    // Verify admin was set correctly
    let stored_admin: Address = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::Admin).unwrap()
    });
    assert_eq!(stored_admin, admin);

    // Update admin (using mock_all_auths to authorize the update)
    env.mock_all_auths();
    client.update_admin(&admin, &new_admin);

    // Verify admin was updated in storage
    let stored_admin_after: Address = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::Admin).unwrap()
    });
    assert_eq!(stored_admin_after, new_admin);
}

#[test]
fn test_new_admin_can_insert_after_update() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let new_admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize contract
    client.init(&admin, &3u32);
    env.mock_all_auths();
    // Update admin
    client.update_admin(&admin, &new_admin);

    // Verify the new admin can insert a leaf (using mock_all_auths to authorize)

    let leaf = U256::from_u32(&env, 100u32);
    client.insert_leaf(&new_admin, &leaf);

    // Verify the insertion succeeded
    let next_index: u32 = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::NextIndex).unwrap()
    });
    assert_eq!(
        next_index, 1,
        "NextIndex should be 1 after insertion by new admin"
    );
}

#[test]
fn test_multiple_insertions() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize with 3 levels (max 8 leaves)
    client.init(&admin, &3u32);

    env.mock_all_auths();

    // Insert 5 leaves
    for i in 0..5 {
        let leaf = U256::from_u32(&env, (i + 1) as u32 * 100u32);
        client.insert_leaf(&admin, &leaf);
    }

    // Verify NextIndex was updated correctly
    let next_index: u32 = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::NextIndex).unwrap()
    });
    assert_eq!(
        next_index, 5,
        "NextIndex should be 5 after inserting 5 leaves"
    );
}

/// Poseidon2 compression function (same as in circuits/src/test/utils/general.rs)
fn poseidon2_compression(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let mut perm = h.permutation(&[left, right]);
    perm[0].add_assign(&left);
    perm[1].add_assign(&right);
    perm[0] // By default, we truncate to one element
}

/// Convert Soroban U256 to off-chain Scalar FpBN256
fn u256_to_scalar(_env: &Env, u256: &U256) -> Scalar {
    // Convert U256 to bytes (big-endian)
    let bytes: Bytes = u256.to_be_bytes();
    let mut bytes_array = [0u8; 32];
    bytes.copy_into_slice(&mut bytes_array);

    // Convert bytes to BigUint
    let biguint = BigUint::from_bytes_be(&bytes_array);

    // Convert BigUint to FpBN256
    Fp256::from(biguint)
}

#[test]
fn test_hash_pair_consistency_1() {
    // Verify that hash_pair on-chain matches poseidon2_compression off-chain
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Test on-chain hash
    let left_u256 = U256::from_u32(&env, 1234u32);
    let right_u256 = U256::from_u32(&env, 6789u32);
    let on_chain_hash = client.hash_pair(&left_u256, &right_u256);

    // Test off-chain hash
    let off_chain_hash = poseidon2_compression(Scalar::from(1234u32), Scalar::from(6789u32));
    let bytes_offchain = off_chain_hash.into_bigint().to_bytes_be();
    let bytes_on_chain = on_chain_hash.to_be_bytes();

    // They should match
    for (i, item) in bytes_offchain.iter().enumerate().take(32) {
        assert_eq!(
            *item,
            bytes_on_chain.get(i as u32).unwrap(),
            "hash_pair compression on-chain should match poseidon2_compression off-chain"
        );
    }
}

#[test]
fn test_hash_pair_consistency_2() {
    // Verify that hash_pair on-chain matches poseidon2_compression off-chain
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let client = ASPMembershipClient::new(&env, &contract_id);

    let a_bytes = [
        38, 87, 116, 229, 180, 73, 149, 93, 95, 216, 55, 138, 202, 129, 16, 169, 208, 107, 174, 63,
        131, 35, 230, 172, 229, 181, 244, 209, 137, 98, 89, 216,
    ];
    let b_bytes = [
        33, 244, 234, 36, 146, 173, 224, 6, 168, 238, 127, 183, 100, 6, 10, 149, 164, 238, 245,
        202, 147, 30, 3, 123, 205, 240, 95, 194, 128, 103, 208, 8,
    ];
    // Test on-chain hash
    let left_u256 = U256::from_be_bytes(&env, &Bytes::from_array(&env, &a_bytes));
    let right_u256 = U256::from_be_bytes(&env, &Bytes::from_array(&env, &b_bytes));
    let on_chain_hash = client.hash_pair(&left_u256, &right_u256);

    // Test off-chain hash
    let off_chain_hash = poseidon2_compression(
        u256_to_scalar(&env, &left_u256),
        u256_to_scalar(&env, &right_u256),
    );
    let bytes_offchain = off_chain_hash.into_bigint().to_bytes_be();
    let bytes_on_chain = on_chain_hash.to_be_bytes();

    // They should match
    for (i, item) in bytes_offchain.iter().enumerate().take(32) {
        assert_eq!(
            *item,
            bytes_on_chain.get(i as u32).unwrap(),
            "hash_pair compression on-chain should match poseidon2_compression off-chain"
        );
    }
}

#[test]
fn test_merkle_consistency() {
    let env = Env::default();
    let contract_id = env.register(ASPMembership, ());
    let admin = Address::generate(&env);
    let client = ASPMembershipClient::new(&env, &contract_id);

    // Initialize with 2 levels (4 leaves)
    let levels = 2u32;
    let num_leaves = 1u32 << levels;
    client.init(&admin, &levels);

    // Mock all auths for testing
    env.mock_all_auths();

    // Precomputed expected state off-chain
    // These were pre-computed to remove any std dependency in the test
    let off_chain_roots: Vec<U256> = vec![
        &env,
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(
                &env,
                &[
                    14, 191, 180, 210, 240, 91, 182, 164, 115, 201, 191, 247, 37, 134, 254, 200, 6,
                    241, 172, 35, 112, 21, 197, 112, 215, 199, 130, 73, 207, 125, 119, 64,
                ],
            ),
        ), //empty tree
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(
                &env,
                &[
                    2, 120, 28, 13, 110, 36, 206, 135, 94, 188, 115, 139, 73, 49, 6, 70, 96, 170,
                    230, 104, 63, 121, 109, 180, 247, 21, 224, 124, 162, 43, 81, 226,
                ],
            ),
        ), // 1 leaf added
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(
                &env,
                &[
                    35, 47, 88, 177, 89, 72, 81, 64, 42, 108, 133, 103, 90, 175, 228, 78, 125, 225,
                    236, 43, 45, 75, 137, 233, 157, 170, 59, 210, 133, 19, 9, 22,
                ],
            ),
        ), // and so on.
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(
                &env,
                &[
                    20, 99, 15, 109, 230, 120, 0, 242, 185, 15, 101, 119, 246, 133, 191, 209, 130,
                    200, 88, 195, 93, 67, 169, 4, 191, 181, 247, 8, 79, 181, 177, 115,
                ],
            ),
        ),
        U256::from_be_bytes(
            &env,
            &Bytes::from_array(
                &env,
                &[
                    23, 225, 197, 156, 139, 142, 232, 34, 202, 96, 195, 138, 141, 144, 133, 159,
                    77, 162, 48, 234, 115, 60, 82, 8, 161, 113, 175, 199, 85, 247, 46, 82,
                ],
            ),
        ),
    ];

    // Get the on-chain root
    let on_chain_root: U256 = env.as_contract(&contract_id, || {
        env.storage().persistent().get(&DataKey::Root).unwrap()
    });

    // Empty roots should match
    assert_eq!(on_chain_root, off_chain_roots.get(0).unwrap());

    // Insert all leaves on-chain
    for i in 0..num_leaves {
        let leaf = U256::from_u32(&env, (i + 1) * 100u32);
        client.insert_leaf(&admin, &leaf);

        // Get the on-chain root
        let on_chain_root: U256 = env.as_contract(&contract_id, || {
            env.storage().persistent().get(&DataKey::Root).unwrap()
        });

        // Enforce roots match after inserting a leaf
        assert_eq!(on_chain_root, off_chain_roots.get(i + 1).unwrap());
    }
}
