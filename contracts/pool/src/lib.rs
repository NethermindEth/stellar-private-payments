#![no_std]

use soroban_sdk::{Address, Bytes, BytesN, Env, Map, Symbol, U256, Vec, contract, contractevent, contractimpl, contracttype, symbol_short, I256};
use soroban_sdk::token::TokenClient;
use soroban_sdk::xdr::ToXdr;

#[contract]
pub struct PoolContract;

const COMMITMENTS: Symbol = symbol_short!("commits");
const NULLIFIERS: Symbol = symbol_short!("nullifs");

pub const HASH_SIZE: usize = 32;
type HashBytes = BytesN<HASH_SIZE>;

#[contracttype]
#[derive(Clone)]
pub struct ExtData {
    pub recipient: Address,
    pub ext_amount: I256,
    pub relayer: Address,
    pub fee: U256,
    pub encrypted_output1: Bytes,
    pub encrypted_output2: Bytes
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
    Verifier2,
    Verifier16,
    MaximumDepositAmount,
    LastBalance,
    Nullifiers
}

#[contractevent]
#[derive(Clone)]
pub struct NewCommitmentEvent {
    #[topic]
    pub commitment: BytesN<32>,
    pub index: u32,
    pub encrypted_output: Bytes,
}

#[contractevent]
#[derive(Clone)]
pub struct NewNullifierEvent {
    #[topic]
    pub nullifier: BytesN<32>,
}

#[contractevent]
#[derive(Clone)]
pub struct PublicKeyEvent {
    #[topic]
    pub owner: Address,
    pub key: Bytes,
}

#[contract]
pub struct TornadoPool;

#[contractimpl]
impl TornadoPool {
    pub fn init( env: Env,
                 token: Address,
                 verifier2: Address,
                 verifier16: Address,
                 maximum_deposit_amount: U256,
                 levels: u32,
                 initial_root: BytesN<32>,) {
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage().persistent().set(&DataKey::Verifier2, &verifier2);
        env.storage().persistent().set(&DataKey::Verifier16, &verifier16);
        env.storage().persistent().set(&DataKey::MaximumDepositAmount, &maximum_deposit_amount);
        env.storage()
            .persistent()
            .set(&DataKey::LastBalance, &U256::from_u32(&env, 0));
        env.storage()
            .persistent()
            .set(&DataKey::Nullifiers, &Map::<BytesN<32>, bool>::new(&env));

    }

    fn calculate_public_amount(env: &Env, ext_amount: I256, fee: U256) -> U256 {
        // TODO: reimplement the exact MAX_EXT_AMOUNT, MAX_FEE, and FIELD_SIZE logic
        let fee_bytes = fee.to_be_bytes();
        let fee_i256 = I256::from_be_bytes(env, &fee_bytes);

        let public_amount = ext_amount.sub(&fee_i256);
        let zero = I256::from_i32(env, 0);

        if public_amount >= zero {
            // positive: just reinterpret I256 -> U256 via bytes
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

    fn get_nullifiers(env: &Env) -> Map<BytesN<32>, bool> {
        env.storage()
            .persistent()
            .get(&DataKey::Nullifiers)
            .unwrap_or(Map::new(env))
    }

    fn set_nullifiers(env: &Env, m: &Map<BytesN<32>, bool>) {
        env.storage().persistent().set(&DataKey::Nullifiers, m);
    }

    fn is_spent (env: &Env, n: BytesN<32>) -> bool {
        // Check visual studio way
        let nulls = Self::get_nullifiers(env);
        nulls.get(n).unwrap_or(false)
    }

    fn mark_spent(env: &Env, n: &BytesN<32>) {
        // Check visual studio way
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
        env.storage().persistent().get(&DataKey::MaximumDepositAmount).unwrap_or(U256::from_u32(env, 0))
    }

    fn hash_ext_data(env: &Env, ext: &ExtData) -> BytesN<32> {
        let payload = ext.clone().to_xdr(env);
        env.crypto().keccak256(&payload).into()
    }

    pub fn transact(env: Env, proof: Proof, ext_data: ExtData, sender: Address) {
        let token = Self::get_token(&env);
        let token_client = TokenClient::new(&env, &token);

        // If extAmount > 0, treat as deposit
        if ext_data.ext_amount > I256::from_i32(&env, 0) {
            // FIX THIS
            // let deposit_u = U256::from_i128(ext_data.ext_amount.to_i128().unwrap() as i128);
            // let max = Self::get_maximum_deposit(&env);
            // if ext_data.ext_amount > max {
            //     panic!("amount is larger than maximumDepositAmount");
            // }

            // token.transfer_from(sender -> this contract)
            let this = env.current_contract_address();
            token_client.transfer(&sender, &this, &ext_data.ext_amount.to_i128().unwrap());
        }

        Self::internal_transact(env, proof, ext_data);
    }

    pub fn internal_transact(env: Env, proof: Proof, ext_data: ExtData) {
        // 1. merkle root check

        // assert!(is_known_root(&env, &proof.root), "unknown root");

        // 2. nullifier checks
        for n in proof.input_nullifiers.iter() {
            assert!(!Self::is_spent(&env, n), "nullifier spent");
        }

        // 3. ext_data_hash check
        let ext_hash = Self::hash_ext_data(&env, &ext_data);

        // 4. public amount check
        assert_eq!(proof.ext_data_hash, ext_hash, "bad ext data hash");
        assert_eq!(
            proof.public_amount,
            // TRY REMOVING CLONES
            Self::calculate_public_amount(&env, ext_data.ext_amount.clone(), ext_data.fee.clone()),
            "bad public amount"
        );

        // 5. zk proof verification
        // assert_eq!(proof.output_commitments.len(), 2, "need 2 outputs"); FIX THIS
        assert!(Self::verify_proof(&env, &proof), "invalid proof");

        // 6. mark nullifiers
        for n in proof.input_nullifiers.iter() {
            // TRY TO REMOVE THE CLONE
            Self::mark_spent(&env, &n);
            NewNullifierEvent { nullifier: n }.publish(&env);
        }

        // 7. withdrawals (extAmount < 0) – only direct L2 transfer, no bridge
        let token = Self::get_token(&env);
        let token_client = TokenClient::new(&env, &token);
        let this = env.current_contract_address();

        if ext_data.ext_amount < I256::from_i32(&env, 0) {
            // withdrawal
            // In Solidity: require(recipient != address(0))
            // Here, you’d enforce some non-empty Address rule if needed.
            // Convert -ext_amount to U256
            let negative = -ext_data.ext_amount;
            // let withdraw_u = U256::from_i128(negative.to_i128().unwrap() as i128);
            token_client.transfer(&this, &ext_data.recipient, &negative);
        }

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


#[contractevent(topics = ["withdraw"], data_format = "single-value")]
struct WithdrawEvent {
    address: Address,
}

#[contractimpl]
impl PoolContract {
    pub fn deposit(env: Env, _from: Address, commitment: BytesN<32>, proof: Proof) {
        if proof.proof.is_empty() {
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
        nullifs.set(nullifier, true);
        env.storage().instance().set(&NULLIFIERS, &nullifs);

        WithdrawEvent { address: to }.publish(&env);
    }
}

mod test;
mod merkle;
