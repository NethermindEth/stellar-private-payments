#![cfg(test)]

use crate::merkle_with_history::MerkleTreeWithHistoryClient;
use crate::merkle_with_history::{DataKey as MerkleKey, MerkleTreeWithHistory};
use crate::{DataKey, ExtData, HASH_SIZE, HashBytes, PoolContract, PoolContractClient, Proof};
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, TryFromVal, U256, Val, Vec, symbol_short,
    testutils::{Address as _, Events as _},
};
use soroban_sdk::{I256, Map, Symbol, contract, contractimpl};

// Helper to get 32 bytes
fn mk_bytesn32(env: &Env, fill: u8) -> HashBytes {
    BytesN::from_array(env, &[fill; HASH_SIZE])
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
            let mut v: Vec<HashBytes> = Vec::new(env);
            v.push_back(mk_bytesn32(env, 0x11));
            v.push_back(mk_bytesn32(env, 0x22));
            v
        },
        output_commitment0: mk_bytesn32(env, 0x33),
        output_commitment1: mk_bytesn32(env, 0x44),
        public_amount: U256::from_u32(env, 0),
        ext_data_hash: mk_bytesn32(env, 0x55),
    }
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
    let reduced = digest_u256.rem_euclid(&field_size(env));
    let mut buf = [0u8; 32];
    reduced.to_be_bytes().copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

fn field_size(env: &Env) -> U256 {
    U256::from_parts(
        env,
        0x3064_4e72_e131_a029,
        0xb850_45b6_8181_585d,
        0x2833_e848_79b9_7091,
        0x43e1_f593_f000_0001,
    )
}

#[contract]
struct MockToken;

#[contractimpl]
impl MockToken {
    pub fn balance(_env: Env, _id: Address) -> i128 {
        0
    }
    pub fn transfer(_env: Env, _from: Address, _to: Address, _amount: i128) {}
    pub fn transfer_from(_env: Env, _from: Address, _to: Address, _amount: i128) {}
    pub fn approve(_env: Env, _from: Address, _spender: Address, _amount: i128) {}
    pub fn allowance(_env: Env, _from: Address, _spender: Address) -> i128 {
        0
    }
}

fn register_mock_token(env: &Env) -> Address {
    env.register(MockToken, ())
}

#[test]
#[should_panic(expected = "already initialized")]
fn pool_init_only_once() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 100);
    let levels = 8u32;
    pool.init(&token, &verifier, &max, &levels);

    // second init should panic
    pool.init(&token, &verifier, &max, &levels);
}

#[test]
#[should_panic(expected = "already initialized")]
fn merkle_init_only_once() {
    let env = Env::default();
    let merkle_id = env.register(MerkleTreeWithHistory, ());
    let merkle = MerkleTreeWithHistoryClient::new(&env, &merkle_id);

    let levels = 8u32;
    merkle.init(&levels);
    merkle.init(&levels);
}

#[test]
fn merkle_insert_updates_root_and_index() {
    let env = Env::default();
    let merkle_id = env.register(MerkleTreeWithHistory, ());
    let merkle = MerkleTreeWithHistoryClient::new(&env, &merkle_id);

    let levels = 3u32;
    merkle.init(&levels);

    let leaf1 = mk_bytesn32(&env, 0x01);
    let leaf2 = mk_bytesn32(&env, 0x02);

    let idx = merkle.insert(&leaf1, &leaf2);
    assert_eq!(idx, 0);

    // last root must be known
    let root = merkle.get_last_root();
    assert!(merkle.is_known_root(&root));

    // nextIndex should now be 2 (stored in instance storage)
    let next: u32 = env.as_contract(&merkle_id, || {
        env.storage().instance().get(&MerkleKey::NextIndex).unwrap()
    });
    assert_eq!(next, 2);
}

#[test]
#[should_panic(expected = "Merkle tree is full. No more leaves can be added")]
fn merkle_insert_fails_when_full() {
    let env = Env::default();
    let merkle_id = env.register(MerkleTreeWithHistory, ());
    let merkle = MerkleTreeWithHistoryClient::new(&env, &merkle_id);

    // levels=1 => capacity of 2 leaves (one insert call)
    let levels = 1u32;
    merkle.init(&levels);

    let leaf1 = mk_bytesn32(&env, 0x0A);
    let leaf2 = mk_bytesn32(&env, 0x0B);
    merkle.insert(&leaf1, &leaf2);

    // second insert should panic
    merkle.insert(&leaf1, &leaf2);
}

#[test]
#[should_panic(expected = "Levels must be within the range [1..32]")]
fn merkle_init_rejects_zero_levels() {
    let env = Env::default();
    let merkle_id = env.register(MerkleTreeWithHistory, ());
    let merkle = MerkleTreeWithHistoryClient::new(&env, &merkle_id);

    let levels = 0u32;
    merkle.init(&levels);
}

#[test]
#[should_panic(expected = "unknown root")]
fn internal_transact_rejects_unknown_root() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    let root = mk_bytesn32(&env, 0xFF); // not a known root
    pool.init(&token, &verifier, &max, &levels);

    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: root.clone(),
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(mk_bytesn32(&env, 0xAB));
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x01),
        output_commitment1: mk_bytesn32(&env, 0x02),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(&env, 0xEE),
    };

    pool.internal_transact(&proof, &ext);
}

#[test]
#[should_panic(expected = "invalid proof")]
fn internal_transact_rejects_empty_proof_bytes() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(&token, &verifier, &max, &levels);

    let root = env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::get_last_root(env.clone())
    });
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let proof = Proof {
        proof: Bytes::new(&env), // empty proof should be rejected
        root,
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(mk_bytesn32(&env, 0xBA));
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x01),
        output_commitment1: mk_bytesn32(&env, 0x02),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
    };

    pool.internal_transact(&proof, &ext);
}

#[test]
#[should_panic(expected = "bad ext data hash")]
fn internal_transact_rejects_bad_ext_hash() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(&token, &verifier, &max, &levels);

    let root = env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::get_last_root(env.clone())
    });
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root,
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(mk_bytesn32(&env, 0xCC));
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x03),
        output_commitment1: mk_bytesn32(&env, 0x04),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: mk_bytesn32(&env, 0x99), // mismatched hash
    };

    pool.internal_transact(&proof, &ext);
}

#[test]
#[should_panic(expected = "bad public amount")]
fn internal_transact_rejects_bad_public_amount() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(&token, &verifier, &max, &levels);

    let root = env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::get_last_root(env.clone())
    });
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root,
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(mk_bytesn32(&env, 0xDD));
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x05),
        output_commitment1: mk_bytesn32(&env, 0x06),
        public_amount: U256::from_u32(&env, 1), // should be 0 for ext_amount=0, fee=0
        ext_data_hash: ext_hash,
    };

    pool.internal_transact(&proof, &ext);
}

#[test]
#[should_panic(expected = "nullifier spent")]
fn internal_transact_marks_nullifiers() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = register_mock_token(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(&token, &verifier, &max, &levels);

    let root = env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::get_last_root(env.clone())
    });
    let nullifier = mk_bytesn32(&env, 0xCD);
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: root.clone(),
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(nullifier.clone());
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x05),
        output_commitment1: mk_bytesn32(&env, 0x06),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash.clone(),
    };

    pool.internal_transact(&proof, &ext);
    // second call with same nullifier should panic
    pool.internal_transact(&proof, &ext);
}

#[test]
fn internal_transact_updates_commitments_and_nullifiers() {
    let env = Env::default();
    let pool_id = env.register(PoolContract, ());
    let pool = PoolContractClient::new(&env, &pool_id);

    let token = Address::generate(&env);
    let verifier = Address::generate(&env);
    let max = U256::from_u32(&env, 1000);
    let levels = 3u32;
    pool.init(&token, &verifier, &max, &levels);

    let root = env.as_contract(&pool_id, || {
        MerkleTreeWithHistory::get_last_root(env.clone())
    });
    let nullifier = mk_bytesn32(&env, 0x22);
    let ext = mk_ext_data(&env, Address::generate(&env), 0, 0);
    let ext_hash = compute_ext_hash(&env, &ext);
    let proof = Proof {
        proof: {
            let mut b = Bytes::new(&env);
            b.push_back(1u8);
            b
        },
        root: root.clone(),
        input_nullifiers: {
            let mut v: Vec<HashBytes> = Vec::new(&env);
            v.push_back(nullifier.clone());
            v
        },
        output_commitment0: mk_bytesn32(&env, 0x09),
        output_commitment1: mk_bytesn32(&env, 0x0A),
        public_amount: U256::from_u32(&env, 0),
        ext_data_hash: ext_hash,
    };

    pool.internal_transact(&proof, &ext);

    // nullifier should be marked spent
    let seen = env.as_contract(&pool_id, || {
        let nulls: Map<HashBytes, bool> = env
            .storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap();
        nulls.get(nullifier.clone()).unwrap_or(false)
    });
    assert!(seen);
}
