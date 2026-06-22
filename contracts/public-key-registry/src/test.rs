use super::*;
use soroban_sdk::{
    Address, Bytes, Env,
    testutils::{Address as _, Events as _},
};

fn account(env: &Env, owner: Address, enc_fill: u8, note_fill: u8) -> Account {
    Account {
        owner,
        encryption_key: Bytes::from_array(env, &[enc_fill; 32]),
        note_key: Bytes::from_array(env, &[note_fill; 32]),
    }
}

#[test]
fn register_saves_registration() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner.clone(), 0x11, 0x22);

    env.mock_all_auths();
    client.register(&account);

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(stored.encryption_key, account.encryption_key);
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn duplicate_registration_is_noop() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner.clone(), 0x11, 0x22);

    env.mock_all_auths();
    client.register(&account);
    let events_after_first = env.events().all().events().len();
    client.register(&account);
    let events_after_second = env.events().all().events().len();

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(events_after_first, 1);
    assert_eq!(events_after_second, 0);
    assert_eq!(stored.encryption_key, account.encryption_key);
    assert_eq!(stored.note_key, account.note_key);
}

#[test]
fn key_rotation_overwrites_registration() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let initial = account(&env, owner.clone(), 0x11, 0x22);
    let rotated = account(&env, owner.clone(), 0x33, 0x44);

    env.mock_all_auths();
    client.register(&initial);
    let first_events = env.events().all().events().len();
    client.register(&rotated);
    let second_events = env.events().all().events().len();

    let stored: Registration = env.as_contract(&contract_id, || {
        env.storage()
            .persistent()
            .get(&DataKey::Registration(owner.clone()))
            .expect("registration should be stored")
    });
    assert_eq!(first_events, 1);
    assert_eq!(second_events, 1);
    assert_eq!(stored.encryption_key, rotated.encryption_key);
    assert_eq!(stored.note_key, rotated.note_key);
}

#[test]
#[should_panic(expected = "Error(Auth, InvalidAction)")]
fn register_requires_owner_auth() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = account(&env, owner, 0x11, 0x22);

    client.register(&account);
}

#[test]
#[should_panic]
fn register_rejects_short_encryption_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = Account {
        owner,
        encryption_key: Bytes::from_slice(&env, &[0x11; 31]),
        note_key: Bytes::from_array(&env, &[0x22; 32]),
    };

    env.mock_all_auths();
    client.register(&account);
}

#[test]
#[should_panic]
fn register_rejects_short_note_key() {
    let env = Env::default();
    let contract_id = env.register(PublicKeyRegistry, ());
    let client = PublicKeyRegistryClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let account = Account {
        owner,
        encryption_key: Bytes::from_array(&env, &[0x11; 32]),
        note_key: Bytes::from_slice(&env, &[0x22; 31]),
    };

    env.mock_all_auths();
    client.register(&account);
}
