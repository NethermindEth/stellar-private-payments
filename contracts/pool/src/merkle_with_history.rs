use soroban_sdk::{Address, Bytes, BytesN, Env, U256, Vec, contract, contractimpl, contracttype};

use soroban_utils::{get_zeroes, hash_pair};

/// How many roots we keep in history
const ROOT_HISTORY_SIZE: u32 = 100;

/// Storage keys for this contract
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Levels,
    CurrentRootIndex,
    NextIndex,
    FilledSubtree(u32),
    Root(u32),
    Controller,
}

#[contract]
pub struct MerkleTreeWithHistory;

#[contractimpl]
impl MerkleTreeWithHistory {
    pub fn init(env: Env, levels: u32) {
        if levels == 0 || levels > 32 {
            panic!("Levels must be within the range [1..32]");
        }

        let storage = env.storage().instance();

        // Prevent re-init
        if storage.get::<DataKey, u32>(&DataKey::Levels).unwrap_or(0) != 0 {
            panic!("already initialized");
        }

        // Store levels
        storage.set(&DataKey::Levels, &levels);

        // get_zeroes returns Vec<U256>
        let zeros_u256: Vec<U256> = get_zeroes(&env);

        // Initialize filledSubtrees[i] = zeros(i) (stored as BytesN<32>)
        for i in 0..levels {
            let z_u256: U256 = zeros_u256.get(i).unwrap();
            let z_bytes = Self::u256_to_bytesn(&env, &z_u256);
            storage.set(&DataKey::FilledSubtree(i), &z_bytes);
        }

        // roots[0] = zeros(levels) (also stored as BytesN<32>)
        let root0_u256: U256 = zeros_u256.get(levels).unwrap();
        let root0_bytes = Self::u256_to_bytesn(&env, &root0_u256);
        storage.set(&DataKey::Root(0), &root0_bytes);

        // currentRootIndex = 0
        storage.set(&DataKey::CurrentRootIndex, &0u32);
        // nextIndex = 0
        storage.set(&DataKey::NextIndex, &0u32);

        // lock to the initializing contract (pool) to prevent external mutation
        let controller = env.current_contract_address();
        storage.set(&DataKey::Controller, &controller);
    }

    pub fn insert(env: Env, leaf1: BytesN<32>, leaf2: BytesN<32>) -> u32 {
        let storage = env.storage().instance();

        // only the initializing contract may mutate
        let controller: Address = storage.get(&DataKey::Controller).expect("not initialized");
        assert_eq!(
            controller,
            env.current_contract_address(),
            "unauthorized merkle access"
        );

        let levels: u32 = storage.get(&DataKey::Levels).expect("tree not initialized");

        let mut next_index: u32 = storage.get(&DataKey::NextIndex).unwrap_or(0);

        // require(_nextIndex != uint32(2)**levels, "Merkle tree is full...")
        let max_leaves = 1u32.checked_shl(levels).expect("levels too large");
        assert_ne!(
            next_index, max_leaves,
            "Merkle tree is full. No more leaves can be added"
        );

        let mut current_index = next_index / 2;

        // zeroes for all levels, from get_zeroes
        let zeros_u256: Vec<U256> = get_zeroes(&env);

        let mut current_level_hash = Self::hash_left_right(&env, &leaf1, &leaf2);

        // bytes32 left; bytes32 right;
        for level in 1..levels {
            let left: BytesN<32>;
            let right: BytesN<32>;

            if current_index % 2 == 0 {
                // even index -> new hash goes on the left, zero on the right
                left = current_level_hash.clone();

                let z_u256: U256 = zeros_u256.get(level).expect("zero value missing");
                right = Self::u256_to_bytesn(&env, &z_u256);

                // filledSubtrees[level] = currentLevelHash;
                storage.set(&DataKey::FilledSubtree(level), &current_level_hash);
            } else {
                // odd index -> existing subtree on the left, new hash on the right
                let stored: BytesN<32> = storage
                    .get(&DataKey::FilledSubtree(level))
                    .expect("filled subtree missing");
                left = stored;
                right = current_level_hash.clone();
            }

            current_level_hash = Self::hash_left_right(&env, &left, &right);
            current_index /= 2;
        }

        // Update root history
        let mut current_root_index: u32 = storage.get(&DataKey::CurrentRootIndex).unwrap_or(0);
        let new_root_index = (current_root_index + 1) % ROOT_HISTORY_SIZE;

        current_root_index = new_root_index;
        storage.set(&DataKey::CurrentRootIndex, &current_root_index);
        storage.set(&DataKey::Root(new_root_index), &current_level_hash);

        // nextIndex += 2;
        let inserted_index = next_index;
        next_index = next_index.checked_add(2).expect("index overflow");
        storage.set(&DataKey::NextIndex, &next_index);

        inserted_index
    }

    pub fn is_known_root(env: &Env, root: &BytesN<32>) -> bool {
        if root == &BytesN::from_array(env, &[0u8; 32]) {
            return false;
        }

        let storage = env.storage().instance();

        let current_root_index: u32 = storage.get(&DataKey::CurrentRootIndex).unwrap_or(0);

        let mut i = current_root_index;

        loop {
            // roots[i]
            if let Some(r) = storage.get::<DataKey, BytesN<32>>(&DataKey::Root(i)) {
                if &r == root {
                    return true;
                }
            }

            if i == 0 {
                i = ROOT_HISTORY_SIZE;
            }
            i -= 1;

            if i == current_root_index {
                break;
            }
        }

        false
    }

    pub fn get_last_root(env: Env) -> BytesN<32> {
        let storage = env.storage().instance();
        let current_root_index: u32 = storage.get(&DataKey::CurrentRootIndex).unwrap_or(0);

        storage
            .get::<DataKey, BytesN<32>>(&DataKey::Root(current_root_index))
            .expect("root not set")
    }

    fn bytesn_to_u256(env: &Env, x: &BytesN<32>) -> U256 {
        let b: Bytes = x.clone().into();
        U256::from_be_bytes(env, &b)
    }

    fn u256_to_bytesn(env: &Env, x: &U256) -> BytesN<32> {
        // U256 -> Bytes
        let b: Bytes = x.to_be_bytes();

        // Bytes -> [u8; 32]
        let mut arr = [0u8; 32];
        b.copy_into_slice(&mut arr); // provided by soroban_sdk::Bytes

        // [u8; 32] -> BytesN<32>
        BytesN::from_array(env, &arr)
    }

    fn hash_left_right(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        let l = Self::bytesn_to_u256(env, left);
        let r = Self::bytesn_to_u256(env, right);
        let h = hash_pair(env, l, r);
        Self::u256_to_bytesn(env, &h)
    }
}
