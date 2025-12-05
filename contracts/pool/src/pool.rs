#![allow(clippy::too_many_arguments)]

use soroban_sdk::token::TokenClient;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    Address, Bytes, BytesN, Env, I256, Map, U256, Vec, contract, contractevent, contractimpl,
    contracttype,
};

use crate::merkle_with_history::MerkleTreeWithHistory;
pub const HASH_SIZE: usize = 32;
pub type HashBytes = BytesN<HASH_SIZE>;

#[contracttype]
#[derive(Clone)]
pub struct ExtData {
    pub recipient: Address,
    pub ext_amount: I256,
    pub fee: U256,
    pub encrypted_output0: Bytes, // By default, we support 2 outputs.
    pub encrypted_output1: Bytes,
}

#[contracttype]
pub struct Proof {
    pub proof: Bytes,
    pub root: HashBytes,
    pub input_nullifiers: Vec<HashBytes>,
    pub output_commitment0: HashBytes,
    pub output_commitment1: HashBytes,
    pub public_amount: U256,
    pub ext_data_hash: HashBytes,
}

#[contracttype]
pub struct Account {
    pub owner: Address,
    pub public_key: Bytes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Token,
    Verifier,
    MaximumDepositAmount,
    Nullifiers,
}

#[contractevent]
#[derive(Clone)]
pub struct NewCommitmentEvent {
    #[topic]
    pub commitment: HashBytes,
    pub index: u32,
    pub encrypted_output: Bytes,
}

#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    #[topic]
    pub nullifier: HashBytes,
}

#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    #[topic]
    pub owner: Address,
    pub key: Bytes,
}

#[contract]
pub struct PoolContract;

#[contractimpl]
impl PoolContract {
    pub fn init(
        env: Env,
        token: Address,
        verifier: Address,
        maximum_deposit_amount: U256,
        levels: u32,
    ) {
        if env.storage().persistent().has(&DataKey::Token) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::Verifier, &verifier);
        env.storage()
            .persistent()
            .set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        env.storage()
            .persistent()
            .set(&DataKey::Nullifiers, &Map::<HashBytes, bool>::new(&env));

        MerkleTreeWithHistory::init(&env, levels);
    }

    /// Maximum abs(ext_amount) allowed (2^248)
    fn max_ext_amount(env: &Env) -> U256 {
        U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
    }

    /// Maximum fee allowed (2^248)
    fn max_fee(env: &Env) -> U256 {
        U256::from_parts(env, 0x0100_0000_0000_0000, 0, 0, 0)
    }

    /// Convert a non-negative I256 into i128 with bounds check.
    /// Panics with a clear message if value is negative or too large.
    fn i256_to_i128_nonneg(env: &Env, v: &I256, context: &str) -> i128 {
        let zero = I256::from_i32(env, 0);

        // Must be >= 0
        assert!(*v >= zero, "{context} must be >= 0",);

        // Must fit into i128 (token amount type)
        v.to_i128().unwrap_or_else(|| {
            panic!("{context} does not fit into i128",);
        })
    }

    fn calculate_public_amount(env: &Env, ext_amount: I256, fee: U256) -> U256 {
        assert!(fee < Self::max_fee(env), "invalid fee");

        let abs_ext = Self::i256_abs_to_u256(env, &ext_amount);
        assert!(abs_ext < Self::max_ext_amount(env), "invalid ext amount");

        let fee_bytes = fee.to_be_bytes();
        let fee_i256 = I256::from_be_bytes(env, &fee_bytes);

        let public_amount = ext_amount.sub(&fee_i256);
        let zero = I256::from_i32(env, 0);

        if public_amount >= zero {
            // positive: just reinterpret I256 to U256 via bytes
            let pa_bytes = public_amount.to_be_bytes();
            U256::from_be_bytes(env, &pa_bytes)
        } else {
            // negative: FIELD_SIZE - uint256(-publicAmount)
            let neg = zero.sub(&public_amount); // = -public_amount
            let neg_bytes = neg.to_be_bytes();
            let neg_u256 = U256::from_be_bytes(env, &neg_bytes);

            let field = Self::field_size(env);
            field.sub(&neg_u256)
        }
    }

    fn field_size(env: &Env) -> U256 {
        // Split into 4x u64 (hi_hi, hi_lo, lo_hi, lo_lo), big-endian
        //
        // 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 BN curve
        U256::from_parts(
            env,
            0x3064_4e72_e131_a029,
            0xb850_45b6_8181_585d,
            0x2833_e848_79b9_7091,
            0x43e1_f593_f000_0001,
        )
    }

    fn get_nullifiers(env: &Env) -> Map<HashBytes, bool> {
        env.storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap_or(Map::new(env))
    }

    fn set_nullifiers(env: &Env, m: &Map<HashBytes, bool>) {
        env.storage().persistent().set(&DataKey::Nullifiers, m);
    }

    fn is_spent(env: &Env, n: &HashBytes) -> bool {
        let nulls = Self::get_nullifiers(env);
        nulls.get(n.clone()).unwrap_or(false)
    }

    fn mark_spent(env: &Env, n: &HashBytes) {
        let mut nulls = Self::get_nullifiers(env);
        nulls.set(n.clone(), true);
        Self::set_nullifiers(env, &nulls);
    }

    fn verify_proof(_env: &Env, _proof: &Proof) -> bool {
        // TODO: add real verifier
        true
    }

    fn get_token(env: &Env) -> Address {
        env.storage().persistent().get(&DataKey::Token).unwrap()
    }

    fn get_maximum_deposit(env: &Env) -> U256 {
        env.storage()
            .persistent()
            .get(&DataKey::MaximumDepositAmount)
            .unwrap_or(U256::from_u32(env, 0))
    }

    /// Hashes the external data using Keccak
    fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
        let payload = ext.clone().to_xdr(env);
        let digest: BytesN<32> = env.crypto().keccak256(&payload).into();
        let digest_u256 = U256::from_be_bytes(env, &Bytes::from(digest));
        let reduced = digest_u256.rem_euclid(&Self::field_size(env));
        let mut buf = [0u8; 32];
        reduced.to_be_bytes().copy_into_slice(&mut buf);
        BytesN::from_array(env, &buf)
    }

    fn i256_abs_to_u256(env: &Env, v: &I256) -> U256 {
        let zero = I256::from_i32(env, 0);
        let abs = if *v >= zero { v.clone() } else { zero.sub(v) };
        U256::from_be_bytes(env, &abs.to_be_bytes())
    }

    pub fn transact(env: Env, proof: Proof, ext_data: ExtData, sender: Address) {
        sender.require_auth();
        let token = Self::get_token(&env);
        let token_client = TokenClient::new(&env, &token);
        let zero = I256::from_i32(&env, 0);

        // If extAmount > 0, treat as deposit
        if ext_data.ext_amount > zero {
            let deposit_u = Self::i256_abs_to_u256(&env, &ext_data.ext_amount);
            let max = Self::get_maximum_deposit(&env);
            assert!(
                deposit_u <= max,
                "amount is larger than maximumDepositAmount"
            );

            let this = env.current_contract_address();
            let amount = Self::i256_to_i128_nonneg(&env, &ext_data.ext_amount, "ext_amount");
            token_client.transfer(&sender, &this, &amount);
        }

        Self::internal_transact(env, proof, ext_data);
    }

    pub fn internal_transact(env: Env, proof: Proof, ext_data: ExtData) {
        assert!(!proof.proof.is_empty(), "invalid proof");

        // 1. merkle root check
        assert!(
            MerkleTreeWithHistory::is_known_root(&env, &proof.root),
            "unknown root"
        );

        // 2. nullifier checks
        for n in proof.input_nullifiers.iter() {
            assert!(!Self::is_spent(&env, &n), "nullifier spent");
        }

        // 3. ext_data_hash check
        let ext_hash = Self::hash_ext_data(&env, &ext_data);
        assert_eq!(proof.ext_data_hash, ext_hash, "bad ext data hash");

        // 4. public amount check
        assert_eq!(
            proof.public_amount,
            Self::calculate_public_amount(&env, ext_data.ext_amount.clone(), ext_data.fee.clone()),
            "bad public amount"
        );

        // 5. zk proof verification
        assert!(Self::verify_proof(&env, &proof), "invalid proof");

        // 6. mark nullifiers
        for n in proof.input_nullifiers.iter() {
            Self::mark_spent(&env, &n);
            NewNullifierEvent { nullifier: n }.publish(&env);
        }

        // 7. withdrawals (extAmount < 0)
        let token = Self::get_token(&env);
        let token_client = TokenClient::new(&env, &token);
        let this = env.current_contract_address();

        let zero = I256::from_i32(&env, 0);

        if ext_data.ext_amount < zero {
            let abs = zero.sub(&ext_data.ext_amount);

            // safe conversion to i128
            let amount: i128 = Self::i256_to_i128_nonneg(&env, &abs, "ext_amount");

            token_client.transfer(&this, &ext_data.recipient, &amount);
        }

        // 10. insert new commitments in Merkle tree
        let idx = MerkleTreeWithHistory::insert(
            env.clone(),
            proof.output_commitment0.clone(),
            proof.output_commitment1.clone(),
        );
        // 11. emit events
        NewCommitmentEvent {
            commitment: proof.output_commitment0,
            index: idx,
            encrypted_output: ext_data.encrypted_output0.clone(),
        }
        .publish(&env);

        NewCommitmentEvent {
            commitment: proof.output_commitment1,
            index: idx + 1,
            encrypted_output: ext_data.encrypted_output1.clone(),
        }
        .publish(&env);
    }

    pub fn register(env: Env, account: Account) {
        account.owner.require_auth();
        PublicKeyEvent {
            owner: account.owner,
            key: account.public_key,
        }
        .publish(&env);
    }
}
