use super::*;
use soroban_sdk::{Address, Bytes, Env, testutils::Address as _};

#[test]
fn register_requires_owner_auth() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = Account {
        owner,
        encryption_key: Bytes::from_array(&env, &[0x11; 32]),
        note_key: Bytes::from_array(&env, &[0x22; 32]),
    };

    env.mock_all_auths();
    client.register(&account);
}
