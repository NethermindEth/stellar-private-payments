use crate::{
    PoolGvkContract, PoolGvkContractClient,
    gvk::{BabyJubJubPoint, TRACEABLE, VIEW_ONLY},
    merkle_with_history::MerkleDataKey,
    policy,
    pool_gvk::DataKey,
};
use asp_membership::{ASPMembership, ASPMembershipClient};
use asp_non_membership::{ASPNonMembership, ASPNonMembershipClient};
use soroban_sdk::{Address, Env, U256, testutils::Address as _};

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

/// Creates and deploys all contracts needed for testing.
///
/// Unlike `pool`'s test setup, no real verifier contract is registered here:
/// this crate's constructor/getters commit doesn't call the verifier, so a
/// plain generated address stands in for it.
fn setup_test_contracts(env: &Env) -> TestSetup {
    let admin = Address::generate(env);

    let asp_membership_address =
        env.register(ASPMembership, (admin.clone(), ASP_MEMBERSHIP_LEVELS));
    let asp_membership_client = ASPMembershipClient::new(env, &asp_membership_address);

    let asp_non_membership_address = env.register(ASPNonMembership, (admin.clone(),));
    let asp_non_membership_client = ASPNonMembershipClient::new(env, &asp_non_membership_address);

    TestSetup {
        admin,
        token: Address::generate(env),
        verifier: Address::generate(env),
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
