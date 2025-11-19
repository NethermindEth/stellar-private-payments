#![no_std]
use soroban_sdk::{contract, contracterror, contractevent, contractimpl, contracttype, symbol_short, vec, Address, Bytes, BytesN, Env, String, Vec, U256};

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
            store.set(&DataKey::FilledSubtrees(lvl), &zeros[lvl]);  
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
    
    pub fn get_zeroes(env: &Env) -> Vec<BytesN<32>> {
        // Hash of 0 at the leaf level is defined as Poseidon2 hash of "XLM" encoded as ASCII.
        // More specifically, t=4, r=3, domain_sep=0. poseidon2(88, 76,77) = poseidon2("XLM").
        // From there, we use the poseidon2 compression function to get the zero hash for each level
        // Big Endian bytes
        let zeros = vec![
            env,
            BytesN::<32>::from_array(env, &[37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187, 158, 240, 248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206]), // 0
            BytesN::<32>::from_array(env, &[33, 244, 234, 36, 146, 173, 224, 6, 168, 238, 127, 183, 100, 6, 10, 149, 164, 238, 245, 202, 147, 30, 3, 123, 205, 240, 95, 194, 128, 103, 208, 8]), // 1
            BytesN::<32>::from_array(env, &[14, 191, 180, 210, 240, 91, 182, 164, 115, 201, 191, 247, 37, 134, 254, 200, 6, 241, 172, 35, 112, 21, 197, 112, 215, 199, 130, 73, 207, 125, 119, 64]), // 2
            BytesN::<32>::from_array(env, &[6, 104, 130, 165, 218, 177, 134, 212, 214, 63, 166, 96, 15, 158, 163, 213, 205, 254, 242, 162, 129, 28, 137, 115, 17, 40, 167, 41, 215, 232, 151, 0]), // 3
            BytesN::<32>::from_array(env, &[6, 93, 179, 20, 141, 141, 165, 50, 155, 234, 236, 80, 66, 120, 92, 105, 242, 206, 7, 9, 226, 109, 70, 139, 218, 30, 37, 92, 89, 155, 86, 134]), // 4
            BytesN::<32>::from_array(env, &[25, 146, 111, 170, 35, 176, 115, 125, 70, 127, 148, 118, 240, 248, 75, 41, 104, 255, 102, 102, 225, 106, 35, 228, 212, 72, 152, 248, 132, 80, 71, 100]), // 5
            BytesN::<32>::from_array(env, &[40, 124, 72, 90, 114, 204, 200, 212, 216, 6, 146, 217, 126, 182, 44, 22, 73, 83, 160, 66, 39, 145, 246, 175, 98, 20, 169, 167, 173, 34, 121, 192]), // 6
            BytesN::<32>::from_array(env, &[31, 114, 158, 16, 62, 125, 65, 95, 114, 141, 201, 69, 227, 182, 226, 196, 10, 192, 203, 54, 158, 83, 43, 165, 10, 86, 151, 144, 205, 222, 42, 204]), // 7
            BytesN::<32>::from_array(env, &[24, 135, 231, 31, 146, 33, 127, 254, 134, 98, 14, 110, 165, 167, 26, 211, 82, 31, 173, 228, 200, 50, 3, 255, 163, 232, 56, 254, 61, 110, 114, 3]), // 8
            BytesN::<32>::from_array(env, &[41, 90, 167, 142, 86, 199, 160, 154, 134, 79, 47, 65, 117, 16, 0, 149, 243, 231, 185, 239, 42, 145, 26, 248, 124, 176, 243, 247, 238, 242, 0, 0]), // 9
            BytesN::<32>::from_array(env, &[5, 23, 3, 42, 121, 107, 3, 64, 220, 95, 157, 242, 139, 31, 211, 32, 218, 186, 36, 213, 164, 83, 53, 161, 55, 22, 115, 0, 238, 54, 136, 40]), // 10
            BytesN::<32>::from_array(env, &[21, 250, 223, 73, 71, 210, 164, 12, 123, 67, 158, 131, 234, 60, 151, 159, 247, 37, 170, 209, 28, 71, 170, 175, 137, 42, 171, 65, 61, 178, 220, 221]), // 11
            BytesN::<32>::from_array(env, &[172, 183, 35, 107, 109, 135, 244, 135, 91, 59, 157, 23, 32, 169, 224, 104, 44, 112, 228, 188, 109, 84, 237, 246, 31, 170, 43, 201, 56, 65, 214, 0]), // 12
            BytesN::<32>::from_array(env, &[9, 131, 109, 217, 5, 77, 86, 10, 230, 14, 166, 168, 3, 52, 4, 179, 228, 3, 9, 246, 238, 77, 23, 10, 203, 146, 230, 102, 126, 134, 199, 117]), // 13
            BytesN::<32>::from_array(env, &[33, 152, 148, 107, 23, 249, 186, 3, 93, 126, 231, 40, 116, 28, 165, 244, 229, 135, 92, 182, 175, 178, 150, 132, 166, 245, 249, 168, 47, 238, 196, 130]), // 14
            BytesN::<32>::from_array(env, &[21, 212, 177, 104, 48, 96, 77, 190, 11, 50, 18, 227, 31, 149, 116, 120, 124, 21, 176, 245, 78, 94, 36, 176, 128, 104, 126, 122, 110, 246, 85, 0]), // 15
            BytesN::<32>::from_array(env, &[45, 7, 247, 62, 4, 207, 10, 83, 128, 55, 186, 7, 86, 22, 81, 172, 151, 155, 176, 14, 23, 5, 199, 93, 220, 149, 22, 236, 75, 138, 106, 118]), // 16
            BytesN::<32>::from_array(env, &[2, 248, 115, 26, 234, 40, 154, 107, 64, 16, 0, 72, 126, 140, 105, 37, 201, 34, 64, 126, 236, 165, 143, 46, 24, 204, 138, 217, 182, 197, 209, 63]), // 17
            BytesN::<32>::from_array(env, &[10, 48, 5, 60, 23, 135, 199, 151, 130, 230, 11, 200, 216, 37, 233, 227, 35, 200, 169, 2, 249, 58, 165, 146, 60, 36, 209, 125, 22, 219, 146, 92]), // 18
            BytesN::<32>::from_array(env, &[14, 163, 5, 141, 153, 88, 186, 95, 228, 65, 251, 215, 157, 201, 104, 244, 73, 33, 93, 222, 230, 97, 70, 22, 26, 252, 243, 76, 52, 191, 164, 144]), // 19
            BytesN::<32>::from_array(env, &[39, 185, 147, 126, 71, 166, 89, 131, 173, 80, 165, 183, 246, 185, 207, 5, 66, 201, 26, 141, 250, 23, 20, 206, 248, 144, 19, 67, 138, 6, 249, 183]), // 20
            BytesN::<32>::from_array(env, &[45, 52, 123, 228, 229, 71, 197, 131, 124, 27, 33, 114, 50, 38, 40, 160, 196, 141, 102, 129, 147, 25, 103, 145, 179, 16, 103, 75, 4, 83, 192, 57]), // 21
            BytesN::<32>::from_array(env, &[3, 242, 70, 27, 53, 184, 146, 252, 140, 88, 151, 6, 40, 61, 16, 131, 244, 210, 214, 107, 228, 249, 126, 70, 26, 186, 242, 240, 111, 137, 207, 253]), // 22
            BytesN::<32>::from_array(env, &[37, 155, 143, 160, 8, 44, 246, 6, 111, 0, 90, 10, 73, 0, 103, 18, 254, 29, 207, 239, 106, 152, 214, 143, 122, 180, 69, 248, 138, 219, 97, 167]), // 23
            BytesN::<32>::from_array(env, &[25, 128, 165, 247, 234, 192, 157, 170, 199, 178, 210, 23, 155, 161, 217, 112, 251, 63, 2, 19, 221, 144, 97, 49, 40, 245, 213, 88, 99, 216, 68, 20]), // 24
            BytesN::<32>::from_array(env, &[28, 252, 217, 74, 171, 194, 60, 172, 212, 204, 171, 34, 232, 125, 35, 3, 32, 13, 9, 176, 48, 66, 178, 4, 127, 3, 210, 224, 222, 245, 126, 133]), // 25
            BytesN::<32>::from_array(env, &[16, 43, 220, 129, 172, 191, 140, 82, 211, 88, 113, 162, 31, 242, 117, 22, 221, 190, 110, 49, 239, 81, 116, 12, 73, 189, 46, 226, 177, 152, 12, 33]), // 26
            BytesN::<32>::from_array(env, &[47, 173, 132, 243, 136, 162, 99, 231, 20, 199, 179, 159, 176, 221, 36, 190, 97, 88, 185, 226, 20, 128, 170, 58, 96, 119, 135, 7, 136, 159, 173, 0]), // 27
            BytesN::<32>::from_array(env, &[42, 206, 148, 45, 48, 190, 203, 54, 159, 28, 253, 2, 91, 83, 148, 214, 238, 76, 151, 245, 89, 48, 4, 138, 24, 251, 80, 17, 40, 200, 119, 119]), // 28
            BytesN::<32>::from_array(env, &[9, 48, 254, 204, 191, 118, 42, 107, 35, 154, 206, 226, 195, 105, 222, 154, 49, 189, 62, 35, 44, 144, 198, 74, 241, 65, 148, 92, 28, 65, 84, 99]), // 29
            BytesN::<32>::from_array(env, &[26, 89, 226, 186, 85, 241, 232, 41, 188, 162, 198, 49, 106, 156, 205, 8, 1, 125, 46, 155, 245, 50, 148, 44, 38, 216, 35, 101, 202, 96, 75, 88]), // 30
            BytesN::<32>::from_array(env, &[26, 142, 132, 12, 132, 226, 251, 82, 18, 214, 31, 9, 173, 95, 145, 214, 167, 10, 131, 7, 78, 148, 39, 114, 239, 116, 180, 45, 18, 161, 31, 80]), // 31
            BytesN::<32>::from_array(env, &[19, 75, 80, 223, 2, 226, 204, 185, 139, 89, 175, 44, 44, 85, 215, 164, 31, 241, 2, 104, 23, 48, 196, 43, 163, 100, 219, 255, 18, 113, 207, 98]), // 32 - Root (when levels=32)
        ];
        zeros
    }
}

mod test;
