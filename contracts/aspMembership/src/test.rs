#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _,},
    Address, Env, U256,
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
    assert_eq!(next_index, 1, "NextIndex should be 1 after insertion by new admin");
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
    assert_eq!(next_index, 5, "NextIndex should be 5 after inserting 5 leaves");
}

