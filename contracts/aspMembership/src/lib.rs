#![no_std]
use soroban_sdk::{contract, contracterror, contractevent, contractimpl, contracttype, symbol_short, vec, Address, Bytes, BytesN, Env, String, Vec};

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
    InvalidMerkleProof = 3,
    RootNotFound = 4,
    InvalidUpdateProof = 5,
    ExpiredAttestation = 6,
}

// Events
#[contractevent(topics = ["DataKey", "leafAdded"], data_format = "single-value")]
struct LeafAddedEvent {
    leaf: BytesN<32>, // Inserted leaf
    index: u32,       // Index where the leaf was inserted
    root: BytesN<32>, // Updated root after insertion
}

#[contract]
pub struct ASPMembership;

#[contractimpl]
impl ASPMembership {
    pub fn init(env: Env, admin: Address, levels: u32)  {
        if levels == 0 || levels >= 32 {
            panic!("Levels must be within the range [1..31]");
        }
        
        let store = env.storage().persistent();
        // Initialize
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Levels, &levels);
        store.set(&DataKey::NextIndex, &0u32);
        // Initialize empty tree (and subtrees)
        let zeros = Self::get_zeroes(&env);
        for lvl in 0..levels {
            store.set(&DataKey::FilledSubtrees(lvl), &zeros[lvl]); // TODO: update with actual zero values to  
        }
        // Set root
        store.set(&DataKey::Root, zeros[levels]);
    }

    pub fn update_admin(env: Env, admin: Address, new_admin: Address) {
        // Enforce only the admin can call the update_admin function
        admin.require_auth();
        let store = env.storage().persistent();
        // Update admin
        store.set(&DataKey::Admin, &new_admin);
    }
    
    pub fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        // TODO: Check inputs are within field range
        // TODO: We need to support Poseidon2
        // We can use the local implementation for now, but we'll need the host function support for efficiency
        let bytes_zero = Bytes::from_slice(&env, &[0; 32]);
        let zero: BytesN<32> = bytes_zero.try_into().expect("bytes to have length 32");
        zero // placeholder TODO: Update with real poseidon2 hash
    }

    pub fn insert_leaf(env: Env, admin: Address, leaf: BytesN<32>) -> Result<(), Error> {
        // Enforce only the admin can call the insert_leaf function
        admin.require_auth();
        
        let store = env.storage().persistent();
        let levels: u32 = store.get(&DataKey::Levels).unwrap();
        let mut current_index: u32 = store.get(&DataKey::NextIndex).unwrap();
        if current_index >= (1 << levels) { // Limit: 2^levels leaves
            Err(Error::MerkleTreeFull)
        } else {
            let mut current_hash = leaf.clone();
            let zeros = Self::get_zeroes(&env);
            for lvl in 0..levels {
                // Check if the leaf is a right (or left) child
                let is_right = current_index & 1 == 1;
                if is_right {
                    let left: BytesN<32> = store.get(&DataKey::FilledSubtrees(lvl)).unwrap();
                    current_hash = Self::hash_pair(&env, &left, &current_hash);
                } else {
                    // We store the filled subtree at the current level with the current hash
                    store.set(&DataKey::FilledSubtrees(lvl), &current_hash);
                    // TODO: Update with the real zero value once we have it
                    current_hash = Self::hash_pair(&env, &current_hash, &zeros[lvl]);
                }
                // Divide the index by 2 to move up in the tree
                current_index >>= 1;
            }
            
            // Emit event
            let root = store.get(&DataKey::FilledSubtrees(levels)).unwrap();
            LeafAddedEvent {
                leaf: leaf.clone(),
                index: store.get(&DataKey::NextIndex).unwrap(),
                root,
            }.publish(&env);
            
            Ok(())
        }
    }

    pub fn insert_two_leafs(env: &Env, admin: Address, leaf: BytesN<32>) -> Result<(), Error> {
        // Enforce only the admin can call the insert_two_leafs function
        admin.require_auth();
        Ok(())
    }
    
    pub fn get_zeroes(env: &Env) -> Vec<BytesN<32>> {
        // TODO: Update placeholders with real values
        // TODO: Check the Bytes::from works with hex Strings
        let zeros = vec![
            env,
            BytesN::<32>::from("0xd0ldE"), // 0
            BytesN::<32>::from("0xd0ldE"), // 1
            BytesN::<32>::from("0xd0ldE"), // 2
            BytesN::<32>::from("0xd0ldE"), // 3
            BytesN::<32>::from("0xd0ldE"), // 4
            BytesN::<32>::from("0xd0ldE"), // 5
            BytesN::<32>::from("0xd0ldE"), // 6
            BytesN::<32>::from("0xd0ldE"), // 7
            BytesN::<32>::from("0xd0ldE"), // 8
            BytesN::<32>::from("0xd0ldE"), // 9
            BytesN::<32>::from("0xd0ldE"), // 10
            BytesN::<32>::from("0xd0ldE"), // 11
            BytesN::<32>::from("0xd0ldE"), // 12
            BytesN::<32>::from("0xd0ldE"), // 13
            BytesN::<32>::from("0xd0ldE"), // 14
            BytesN::<32>::from("0xd0ldE"), // 15
            BytesN::<32>::from("0xd0ldE"), // 16
            BytesN::<32>::from("0xd0ldE"), // 17
            BytesN::<32>::from("0xd0ldE"), // 18
            BytesN::<32>::from("0xd0ldE"), // 19
            BytesN::<32>::from("0xd0ldE"), // 20
            BytesN::<32>::from("0xd0ldE"), // 21
            BytesN::<32>::from("0xd0ldE"), // 22
            BytesN::<32>::from("0xd0ldE"), // 23
            BytesN::<32>::from("0xd0ldE"), // 24
            BytesN::<32>::from("0xd0ldE"), // 25
            BytesN::<32>::from("0xd0ldE"), // 26
            BytesN::<32>::from("0xd0ldE"), // 27
            BytesN::<32>::from("0xd0ldE"), // 28
            BytesN::<32>::from("0xd0ldE"), // 29
            BytesN::<32>::from("0xd0ldE"), // 30
            BytesN::<32>::from("0xd0ldE"), // 31
            BytesN::<32>::from("0xd0ldE"), // 32 - Root (when levels=32)
        ];
        zeros
    }
}

mod test;
