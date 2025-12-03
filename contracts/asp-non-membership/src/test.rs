#![cfg(test)]

use super::*;
use soroban_sdk::{Address, Bytes, Env, U256, testutils::Address as _};

#[test]
fn test_init() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    client.init(&admin);

    // Verify root is zero (empty tree)
    let root = client.get_root();
    assert_eq!(root, U256::from_u32(&env, 0u32));
}

#[test]
fn test_insert_leaf() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    env.mock_all_auths();

    // Initialize contract with admin address
    client.init(&admin);

    // Insert leaf
    let key = U256::from_u32(&env, 1u32);
    let value = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key, &value);

    // Root should have changed
    let root = client.get_root();
    assert_ne!(root, U256::from_u32(&env, 0u32));
}

#[test]
fn test_update_leaf() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    env.mock_all_auths();
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize contract with admin address
    client.init(&admin);
    // Insert and update leaf
    let key = U256::from_u32(&env, 1u32);
    let value1 = U256::from_u32(&env, 42u32);
    let value2 = U256::from_u32(&env, 100u32);
    // Insert
    client.insert_leaf(&key, &value1);
    let root1 = client.get_root();
    // Update leaf with new value
    client.update_leaf(&key, &value2);
    let root2 = client.get_root();

    // Root should have changed
    assert_ne!(root1, root2);
}

#[test]
fn test_insert_multiple_keys() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    // Mock all auths for testing purposes
    env.mock_all_auths();
    client.init(&admin);

    // Insert multiple keys
    for i in 1..=5 {
        let key = U256::from_u32(&env, i);
        let value = U256::from_u32(&env, i * 10);
        client.insert_leaf(&key, &value);
    }

    // Root should be non-zero
    let root = client.get_root();
    assert_ne!(root, U256::from_u32(&env, 0u32));
}

#[test]
#[should_panic]
fn test_duplicate_insert_fails() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    // Mock auth and init the contract
    env.mock_all_auths();
    client.init(&admin);

    let key = U256::from_u32(&env, 1u32);
    let value = U256::from_u32(&env, 42u32);
    let second_value = U256::from_u32(&env, 24u32);

    // First insert should succeed
    client.insert_leaf(&key, &value);

    // Second insert with same key should fail
    client.insert_leaf(&key, &second_value);
}

#[test]
#[should_panic]
fn test_update_nonexistent_key_fails() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    // Mock auth and init the contract
    env.mock_all_auths();
    client.init(&admin);

    let key = U256::from_u32(&env, 1u32);
    let value = U256::from_u32(&env, 42u32);

    client.update_leaf(&key, &value);
}

/// Test that matches the circuits test: insert key=1, value=42
#[test]
fn test_root_consistency_with_circuits_insert_1_42() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    env.mock_all_auths();
    // Initialize contract with admin address
    client.init(&admin);

    // Insert leaf
    let key = U256::from_u32(&env, 1u32);
    let value = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key, &value);

    let root = client.get_root();

    // Expected root from circuits/src/test/utils/sparse_merkle_tree.rs test_new_tree
    let expected_root_bytes = [
        36, 47, 214, 99, 44, 86, 82, 102, 2, 180, 27, 116, 85, 152, 220, 251, 240, 186, 68, 254,
        31, 87, 13, 109, 107, 75, 208, 28, 34, 234, 154, 162,
    ];

    let expected_root = U256::from_be_bytes(&env, &Bytes::from_array(&env, &expected_root_bytes));
    assert_eq!(root, expected_root, "Root should match the circuits test");
}

/// Test that matches the circuits test: insert key=1, value=42, then update to value=100
#[test]
fn test_root_consistency_with_circuits_update_1_100() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);
    env.mock_all_auths();
    client.init(&admin);

    let key = U256::from_u32(&env, 1u32);
    let value1 = U256::from_u32(&env, 42u32);
    let value2 = U256::from_u32(&env, 100u32);

    // Insert
    client.insert_leaf(&key, &value1);

    // Update
    client.update_leaf(&key, &value2);

    let root = client.get_root();

    // Expected root from circuits test: 12569474685065514766800302626776627658362290519786081498087070427717152263146
    // Hex: 0x1bca121020a7041a503dabbb08f8ed11fd45bf8c2c0851e9db040ea7ae6fcbea
    let expected_root_bytes = [
        27, 202, 18, 16, 32, 167, 4, 26, 80, 61, 171, 187, 8, 248, 237, 17, 253, 69, 191, 140, 44,
        8, 81, 233, 219, 4, 14, 167, 174, 111, 203, 234,
    ];

    let expected_root = U256::from_be_bytes(&env, &Bytes::from_array(&env, &expected_root_bytes));
    assert_eq!(
        root, expected_root,
        "Root should match the circuits test after update"
    );
}

/// Test that matches the circuits test: insert key=1, value=42, then insert key=2, value=324
#[test]
fn test_root_consistency_with_circuits_insert_2_324() {
    let env = Env::default();
    let contract_id = env.register(ASPNonMembership, ());
    let admin = Address::generate(&env);
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    env.mock_all_auths();
    client.init(&admin);

    // Insert key=1, value=42
    let key1 = U256::from_u32(&env, 1u32);
    let value1 = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key1, &value1);

    // Insert key=2, value=324
    let key2 = U256::from_u32(&env, 2u32);
    let value2 = U256::from_u32(&env, 324u32);
    client.insert_leaf(&key2, &value2);

    let root = client.get_root();

    // Expected root from circuits test: 5609325791308905881148228299085922973290228927442613473721605762655624624574
    // Hex: 0x0c66c411436951f3846f7b784b3da933cb56d973afdcec1b1d56af709df7f9be
    let expected_root_bytes = [
        12, 102, 196, 17, 67, 105, 81, 243, 132, 111, 123, 120, 75, 61, 169, 51, 203, 86, 217, 115,
        175, 220, 236, 27, 29, 86, 175, 112, 157, 247, 249, 190,
    ];

    let expected_root = U256::from_be_bytes(&env, &Bytes::from_array(&env, &expected_root_bytes));
    assert_eq!(
        root, expected_root,
        "Root should match the circuits test after inserting key=2, value=324"
    );
}

#[test]
fn test_find_key_public_method() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize the contract and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Test 1: Find in empty tree
    let key1 = U256::from_u32(&env, 42);
    let result = client.find_key(&key1);
    assert!(!result.found, "Key should not be found in empty tree");
    assert_eq!(result.siblings.len(), 0, "No siblings in empty tree");
    assert_eq!(
        result.found_value,
        U256::from_u32(&env, 0),
        "Found value should be zero"
    );
    assert_eq!(
        result.not_found_key, key1,
        "Not found key should be the query key"
    );
    assert_eq!(
        result.not_found_value,
        U256::from_u32(&env, 0),
        "Not found value should be zero"
    );
    assert!(result.is_old0, "old0 should be true");

    // Insert a key
    let value1 = U256::from_u32(&env, 100);
    client.insert_leaf(&key1, &value1);

    // Test 2: Find existing key
    let result = client.find_key(&key1);
    assert!(result.found, "Key should be found");
    assert_eq!(result.siblings.len(), 0, "No siblings for single leaf");
    assert_eq!(
        result.found_value, value1,
        "Found value should match inserted value"
    );
    assert_eq!(
        result.not_found_key,
        U256::from_u32(&env, 0),
        "Not found key should be zero when found"
    );
    assert_eq!(
        result.not_found_value,
        U256::from_u32(&env, 0),
        "Not found value should be zero when found"
    );
    assert!(!result.is_old0, "old0 should be false when key exists");

    // Test 3: Find a non-existent key whose path collides with an existing key
    let key2 = U256::from_u32(&env, 43);
    client.insert_leaf(&key2, &U256::from_u32(&env, 200));
    let key3 = U256::from_u32(&env, 99); // Will collide with key2
    let result = client.find_key(&key3);
    assert!(!result.found, "Key should not be found");
    assert!(
        !result.siblings.is_empty(),
        "Should have siblings in populated tree"
    );
    assert_eq!(
        result.found_value,
        U256::from_u32(&env, 0),
        "Found value should be zero"
    );
    assert_eq!(
        result.not_found_key,
        U256::from_u32(&env, 43),
        "Should collide with key2"
    );
    assert_eq!(
        result.not_found_value,
        U256::from_u32(&env, 200),
        "Should collide with key2 value"
    );
    assert!(
        !result.is_old0,
        "Should not be true as we found a collision"
    );
}

#[test]
fn test_delete_single_leaf() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Insert a single key
    let key = U256::from_u32(&env, 1u32);
    let value = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key, &value);

    let root_before = client.get_root();
    assert_ne!(
        root_before,
        U256::from_u32(&env, 0),
        "Root should not be zero after insert"
    );

    // Delete the key
    client.delete_leaf(&key);

    // Tree should be empty now
    let root_after = client.get_root();
    assert_eq!(
        root_after,
        U256::from_u32(&env, 0),
        "Root should be zero after deleting only key"
    );

    // Key should not be found
    let result = client.find_key(&key);
    assert!(!result.found, "Key should not be found after deletion");
    assert!(result.is_old0, "Should be old0 (empty tree)");
}

#[test]
fn test_delete_from_two_keys() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Insert two keys
    let key1 = U256::from_u32(&env, 1u32);
    let value1 = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key1, &value1);

    let key2 = U256::from_u32(&env, 2u32);
    let value2 = U256::from_u32(&env, 324u32);
    client.insert_leaf(&key2, &value2);

    // Delete key2
    client.delete_leaf(&key2);

    let root_after_delete = client.get_root();

    // key2 should not be found
    let result2 = client.find_key(&key2);
    assert!(!result2.found, "key2 should not be found after deletion");

    // key1 should still be found
    let result1 = client.find_key(&key1);
    assert!(result1.found, "key1 should still be found");
    assert_eq!(result1.found_value, value1, "key1 value should match");

    // Root should match what we'd get from inserting just key1 (see previous tests)
    let expected_root_bytes = [
        36, 47, 214, 99, 44, 86, 82, 102, 2, 180, 27, 116, 85, 152, 220, 251, 240, 186, 68, 254,
        31, 87, 13, 109, 107, 75, 208, 28, 34, 234, 154, 162,
    ];
    let expected_root = U256::from_be_bytes(&env, &Bytes::from_array(&env, &expected_root_bytes));

    assert_eq!(
        root_after_delete, expected_root,
        "Root should match single key1 tree"
    );
}

#[test]
fn test_delete_from_multiple_keys() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Insert multiple keys
    let keys_values: [(u32, u32); 5] = [(1, 10), (2, 20), (3, 30), (4, 40), (5, 50)];

    for (k, v) in keys_values.iter() {
        let key = U256::from_u32(&env, *k);
        let value = U256::from_u32(&env, *v);
        client.insert_leaf(&key, &value);
    }

    // Delete key 3
    let key_to_delete = U256::from_u32(&env, 3u32);
    client.delete_leaf(&key_to_delete);

    // key 3 should not be found
    let result = client.find_key(&key_to_delete);
    assert!(!result.found, "Deleted key should not be found");

    // Other keys should still be found
    for (k, v) in keys_values.iter() {
        if *k != 3 {
            let key = U256::from_u32(&env, *k);
            let value = U256::from_u32(&env, *v);
            let result = client.find_key(&key);
            assert!(result.found, "Key {k} should still be found");
            assert_eq!(result.found_value, value, "Value for key {k} should match");
        }
    }
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")] // KeyNotFound = 2
fn test_delete_nonexistent_key_fails() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Insert a key
    let key1 = U256::from_u32(&env, 1u32);
    let value1 = U256::from_u32(&env, 42u32);
    client.insert_leaf(&key1, &value1);

    // Try to delete a different key that doesn't exist
    let key_nonexistent = U256::from_u32(&env, 99u32);
    client.delete_leaf(&key_nonexistent);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")] // KeyNotFound = 2
fn test_delete_from_empty_tree_fails() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let contract_id = env.register(ASPNonMembership, ());
    let client = ASPNonMembershipClient::new(&env, &contract_id);

    // Initialize and mock auths
    client.init(&admin);
    env.mock_all_auths();

    // Try to delete from empty tree
    let key = U256::from_u32(&env, 1u32);
    client.delete_leaf(&key);
}
