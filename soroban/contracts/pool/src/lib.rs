#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, BytesN, Env, String, Vec, U256};
use soroban_sdk::xdr::Uint256;

#[contract]
pub struct PoolContract ;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtData {
    pub recipient: Address,
    pub ext_amount: i128, // that was supposed to be 256, lets investigate if we can keep it 128
}

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

#[contracttype]
pub struct Account {
    pub owner: Address,
    pub public_key: Bytes,
}

// ---------- Event payload types ----------
#[contracttype]
pub struct NewCommitmentData {
    pub commitment: BytesN<32>,
    pub index: u32,            
    pub encrypted_output: Bytes,
}

#[contracttype]
pub struct NewNullifierData {
    pub nullifier: BytesN<32>,
}

#[contracttype]
pub struct PublicKeyData {
    pub key: Bytes,          
}


#[contractimpl]
impl PoolContract {
    pub fn hello(env: Env, to: String) -> Vec<String> {
        vec![&env, String::from_str(&env, "Hello"), to]
    }
    
    // To be added when we have the verifier and the merkle history
    // pub fn __constructor(env: Env, to: String) -> Vec<String> {
    //     
    // }


    // pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
    //     env.storage().persistent().has(&DataKey::Nullifier(nullifier))
    // }
    // 
    // pub fn mark_spent(env: &Env, nullifier: &BytesN<32>) {
    //     // We just store `true`; later we only check presence via `has()`.
    //     env.storage().persistent().set(&DataKey::Nullifier(nullifier.clone()), &true);
    // }

   
    // ---------- Emit helpers ----------
    pub fn emit_new_commitment(env: &Env, commitment: BytesN<32>, index: u32, encrypted_output: Bytes) {
        // Topics: event name only (you could also include the index if you want to filter by it)
        env.events().publish(
            (symbol_short!("new_comm"),),
            NewCommitmentData {
                commitment,
                index,
                encrypted_output,
            },
        );
    }

    pub fn emit_new_nullifier(env: &Env, nullifier: BytesN<32>) {
        // Topics: event name only
        env.events().publish(
            (symbol_short!("new_null"),),
            NewNullifierData { nullifier },
        );
    }

    pub fn emit_public_key(env: &Env, owner: Address, key: Bytes) {
        // In Solidity `owner` was `indexed`, so put it in topics
        env.events().publish(
            (symbol_short!("pk"), owner),
            PublicKeyData { key },
        );
    }
}

mod test;
