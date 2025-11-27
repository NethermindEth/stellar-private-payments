use soroban_sdk::{
    Address, Env, U256, Vec, contract, contracterror, contractevent, contractimpl, contracttype,
};
use soroban_utils::{get_zeroes, poseidon2_compress};

#[contracttype]
#[derive(Clone, Debug)]
enum DataKey {
    Admin,
    FilledSubtrees(u32),
    Zeroes(u32),
    Levels,
    NextIndex,
    Root,
}

// Errors
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotAuthorized = 1,
    MerkleTreeFull = 2,
}

// Events
#[contractevent(topics = ["LeafAdded"])]
struct LeafAddedEvent {
    leaf: U256, // Inserted leaf
    index: u32, // Index where the leaf was inserted
    root: U256, // Updated root after insertion
}

#[contract]
pub struct ASPMembership;

#[contractimpl]
impl ASPMembership {
    pub fn init(env: Env, admin: Address, levels: u32) {
        if levels == 0 || levels > 32 {
            panic!("Levels must be within the range [1..32]");
        }

        let store = env.storage().persistent();
        // Initialize
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Levels, &levels);
        store.set(&DataKey::NextIndex, &0u32);
        // Initialize an empty tree (and subtrees)
        let zeros: Vec<U256> = get_zeroes(&env);
        for lvl in 0..levels + 1 {
            let zero_val = zeros.get(lvl).unwrap();
            store.set(&DataKey::FilledSubtrees(lvl), &zero_val);
        }
        // Set root
        let root_val = zeros.get(levels).unwrap();
        store.set(&DataKey::Root, &root_val);
    }

    pub fn update_admin(env: Env, admin: Address, new_admin: Address) {
        // Enforce only the admin can call the update_admin function
        admin.require_auth();
        let store = env.storage().persistent();
        // Update admin
        store.set(&DataKey::Admin, &new_admin);
    }

    pub fn hash_pair(env: &Env, left: U256, right: U256) -> U256 {
        poseidon2_compress(env, left, right)
    }

    pub fn insert_leaf(env: Env, admin: Address, leaf: U256) -> Result<(), Error> {
        // Enforce only the admin can call the insert_leaf function
        admin.require_auth();
        let store = env.storage().persistent();
        let levels: u32 = store.get(&DataKey::Levels).unwrap();
        let actual_index: u32 = store.get(&DataKey::NextIndex).unwrap();
        let mut current_index = actual_index;

        if current_index >= (1 << levels) {
            // Limit: 2^levels leaves
            Err(Error::MerkleTreeFull)
        } else {
            let mut current_hash = leaf.clone();
            let zeros = get_zeroes(&env);
            for lvl in 0..levels {
                // Check if the leaf is a right (or left) child
                let is_right = current_index & 1 == 1;
                if is_right {
                    let left: U256 = store.get(&DataKey::FilledSubtrees(lvl)).unwrap();
                    current_hash = poseidon2_compress(&env, left, current_hash);
                } else {
                    // We store the filled subtree at the current level with the current hash
                    store.set(&DataKey::FilledSubtrees(lvl), &current_hash);
                    let zero_val = zeros.get(lvl).unwrap();
                    current_hash = poseidon2_compress(&env, current_hash, zero_val);
                }
                // Divide the index by 2 to move up in the tree
                current_index >>= 1;
            }

            // Update the root with the final hash
            store.set(&DataKey::Root, &current_hash);

            // Emit event
            LeafAddedEvent {
                leaf: leaf.clone(),
                index: store.get(&DataKey::NextIndex).unwrap(),
                root: current_hash,
            }
            .publish(&env);

            // Update NextIndex
            store.set(&DataKey::NextIndex, &(actual_index + 1));
            Ok(())
        }
    }
}

mod test;
