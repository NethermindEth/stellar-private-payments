#![cfg(test)]

use super::*;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, TryFromVal, U256, Val, Vec, symbol_short,
    testutils::{Address as _, Events as _},
};

// Helper to get 32 bytes
fn mk_bytesn32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

// non-empty placeholder proof
fn mk_proof(env: &Env) -> Proof {
    Proof {
        proof: {
            let mut b = Bytes::new(env);
            b.push_back(1u8);
            b
        },
        root: mk_bytesn32(env, 0xAA),
        input_nullifiers: {
            let mut v: Vec<BytesN<32>> = Vec::new(env);
            v.push_back(mk_bytesn32(env, 0x11));
            v.push_back(mk_bytesn32(env, 0x22));
            v
        },
        output_commitment0: mk_bytesn32(env, 0x33),
        output_commitment1: mk_bytesn32(env, 0x44),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(env, 0x55),
    }
}

#[test]
#[should_panic(expected = "invalid proof")]
fn deposit_rejects_empty_proof() {
    let env = Env::default();
    let contract_id = env.register(PoolContract, ());
    let client = PoolContractClient::new(&env, &contract_id);

    let from = Address::generate(&env);
    let commitment = mk_bytesn32(&env, 0x01);

    // Empty proof, it should panic in the check
    let empty_proof = Proof {
        proof: Bytes::new(&env),
        root: mk_bytesn32(&env, 0xAA),
        input_nullifiers: Vec::new(&env),
        output_commitment0: mk_bytesn32(&env, 0xBB),
        output_commitment1: mk_bytesn32(&env, 0xCC),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(&env, 0xDD),
    };

    client.deposit(&from, &commitment, &empty_proof);
}

#[test]
fn deposit_appends_commitment() {
    let env = Env::default();
    let contract_id = env.register(PoolContract, ());
    let client = PoolContractClient::new(&env, &contract_id);

    let from = Address::generate(&env);

    let comm1 = mk_bytesn32(&env, 0x01);
    let comm2 = mk_bytesn32(&env, 0x02);

    client.deposit(&from, &comm1, &mk_proof(&env));
    client.deposit(&from, &comm2, &mk_proof(&env));

    let commits: Vec<BytesN<32>> = env.as_contract(&contract_id, || {
        env.storage().instance().get(&COMMITMENTS).unwrap()
    });

    assert_eq!(commits.len(), 2);
    assert_eq!(commits.get(0).unwrap(), comm1);
    assert_eq!(commits.get(1).unwrap(), comm2);
}

#[test]
fn withdraw_records_nullifier() {
    let env = Env::default();
    let contract_id = env.register(PoolContract, ());
    let client = PoolContractClient::new(&env, &contract_id);

    let to = Address::generate(&env);
    let nullifier = mk_bytesn32(&env, 0xAB);

    client.withdraw(&to, &nullifier);

    // Check that a Withdraw event was emitted with `to`
    let mut found = false;
    let events = env.events().all();
    assert!(!events.is_empty(), "no events recorded");

    for e in env.events().all() {
        let topics: Vec<Val> = e.1.clone();
        if topics.len() >= 1 {
            let topic: Val = topics.get_unchecked(0);
            let topic_sym: Option<Symbol> =
                <Symbol as TryFromVal<Env, Val>>::try_from_val(&env, &topic).ok();

            if topic_sym == Some(symbol_short!("withdraw")) {
                let data: Val = e.2.clone();
                let addr: Option<Address> =
                    <Address as TryFromVal<Env, Val>>::try_from_val(&env, &data).ok();

                if addr == Some(to.clone()) {
                    found = true;
                    break;
                }
            }
        }
    }

    assert!(found, "expected Withdraw event with recipient");

    // Check nullifier marked as used in storage
    let seen: bool = env.as_contract(&contract_id, || {
        let nullifs: Map<BytesN<32>, bool> = env.storage().instance().get(&NULLIFIERS).unwrap();
        nullifs.get(nullifier.clone()).unwrap()
    });
    assert!(seen);
}

#[test]
#[should_panic(expected = "nullifier already used")]
fn withdraw_double_spend_panics() {
    let env = Env::default();
    let contract_id = env.register(PoolContract, ());
    let client = PoolContractClient::new(&env, &contract_id);

    let to = Address::generate(&env);
    let nullifier = mk_bytesn32(&env, 0xEF);

    client.withdraw(&to, &nullifier);
    // Using the same nullifier again should panic
    client.withdraw(&to, &nullifier);
}
