#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Bytes, BytesN, Env, TryFromVal, Vec, U256};

use soroban_utils::{get_zeroes, hash_pair as hash_pair_util, hash_pair};


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
        if storage
            .get::<DataKey, u32>(&DataKey::Levels)
            .unwrap_or(0) != 0
        {
            panic!("already initialized");
        }

        // Store levels
        storage.set(&DataKey::Levels, &levels);
        let zeros: Vec<U256> = get_zeroes(&env);

        // Initialize filledSubtrees[i] = zeros(i)
        for i in 0..levels {
            let z = zeros.get(i).unwrap();
            storage.set(&DataKey::FilledSubtree(i), &z);
        }

        // roots[0] = zeros(levels)
        let root0 = zeros.get(levels).unwrap();
        storage.set(&DataKey::Root(0), &root0);

        // currentRootIndex = 0
        storage.set(&DataKey::CurrentRootIndex, &0u32);
        // nextIndex = 0
        storage.set(&DataKey::NextIndex, &0u32);
    }

    pub fn insert(env: Env, leaf1: BytesN<32>, leaf2: BytesN<32>) -> u32 {
        let storage = env.storage().instance();

        let levels: u32 = storage
            .get(&DataKey::Levels)
            .expect("tree not initialized");

        let mut next_index: u32 = storage
            .get(&DataKey::NextIndex)
            .unwrap_or(0);

        // require(_nextIndex != uint32(2)**levels, "Merkle tree is full...")
        let max_leaves = 1u32.checked_shl(levels).expect("levels too large");
        assert_ne!(next_index, max_leaves, "Merkle tree is full. No more leaves can be added");

        let mut current_index = next_index / 2;

        let mut current_level_hash = Self::hash_left_right(&env, &leaf1, &leaf2);

        // bytes32 left; bytes32 right;
        for level in 1..levels {
            let left: BytesN<32>;
            let right: BytesN<32>;

            if current_index % 2 == 0 {
                // even index -> new hash goes on the left, zero on the right
                left = current_level_hash.clone();
                right = zeros(&env, level);
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

            current_level_hash = hash_left_right(&env, &left, &right);
            current_index /= 2;
        }

        // Update root history
        let mut current_root_index: u32 = storage
            .get(&DataKey::CurrentRootIndex)
            .unwrap_or(0);
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

        let current_root_index: u32 = storage
            .get(&DataKey::CurrentRootIndex)
            .unwrap_or(0);

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
        let current_root_index: u32 = storage
            .get(&DataKey::CurrentRootIndex)
            .unwrap_or(0);
        storage
            .get::<DataKey, BytesN<32>>(&DataKey::Root(current_root_index))
            .expect("root not set")
    }

    fn bytesn_to_u256(env: &Env, x: &BytesN<32>) -> U256 {
        let b: Bytes = x.clone().into();
        U256::from_be_bytes(env, &b)
    }

    fn u256_to_bytesn(env: &Env, x: &U256) -> BytesN<32> {
        let b = x.to_be_bytes();
        BytesN::try_from_val(env, &b).unwrap()
    }

    fn hash_left_right(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        let l = Self::bytesn_to_u256(env, left);
        let r = Self::bytesn_to_u256(env, right);
        let h = hash_pair(env, l, r);
        Self::u256_to_bytesn(env, &h)
    }

}