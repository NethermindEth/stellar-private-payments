#![no_std]

use soroban_sdk::{
    Address, Bytes, BytesN, Env, Map, Symbol, U256, Vec, contract, contractevent, contractimpl,
    contracttype, symbol_short,
};

#[contract]
pub struct PoolContract;

const COMMITMENTS: Symbol = symbol_short!("commits");
const NULLIFIERS: Symbol = symbol_short!("nullifs");

#[contracttype]
pub struct Proof {
    pub proof: Bytes,
    pub root: BytesN<32>,
    pub input_nullifiers: Vec<BytesN<32>>,
    pub output_commitment0: BytesN<32>,
    pub output_commitment1: BytesN<32>,
    pub public_amount: U256,
    pub ext_data_hash: BytesN<32>,
}

#[contractevent(topics = ["withdraw"], data_format = "single-value")]
struct WithdrawEvent {
    address: Address,
}

#[contractimpl]
impl PoolContract {
    pub fn deposit(env: Env, _from: Address, commitment: BytesN<32>, proof: Proof) {
        if proof.proof.len() == 0 {
            panic!("invalid proof");
        }
        // Verify proof

        let mut commits: Vec<BytesN<32>> = env
            .storage()
            .instance()
            .get(&COMMITMENTS)
            .unwrap_or(Vec::new(&env));
        commits.push_back(commitment);
        env.storage().instance().set(&COMMITMENTS, &commits);
    }

    pub fn withdraw(env: Env, to: Address, nullifier: BytesN<32>) {
        // Prevent double-withdraw
        let mut nullifs: Map<BytesN<32>, bool> = env
            .storage()
            .instance()
            .get(&NULLIFIERS)
            .unwrap_or(Map::new(&env));
        if nullifs.contains_key(nullifier.clone()) {
            panic!("nullifier already used");
        }
        nullifs.set(nullifier.clone(), true);
        env.storage().instance().set(&NULLIFIERS, &nullifs);

        WithdrawEvent { address: to }.publish(&env);
    }
}

mod test;
