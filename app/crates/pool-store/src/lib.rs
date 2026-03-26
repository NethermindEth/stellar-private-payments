//! In-memory Poseidon2 Merkle tree with SQLite-backed pool state.
//! Port of `app/js/state/pool-store.js`.

use storage::{
    Storage,
    types::{PoolEncryptedOutput, PoolLeaf, PoolNullifier},
};
use utils::{
    bytes_to_hex,
    merkle::{MerkleProof, MerkleTree, hex_to_scalar},
};

/// Pool state: in-memory Poseidon2 Merkle tree with SQLite-backed persistence.
pub struct PoolStore {
    db: Storage,
    tree: MerkleTree,
}

impl PoolStore {
    /// Opens the pool store and rebuilds the in-memory tree from `db`.
    pub fn open(db: Storage) -> anyhow::Result<Self> {
        let tree = MerkleTree::new_for_depth(utils::TREE_DEPTH)?;
        let mut store = Self { db, tree };
        store.rebuild_tree()?;
        Ok(store)
    }

    /// Rebuilds the in-memory tree from persisted leaves. Returns the leaf
    /// count.
    pub fn rebuild_tree(&mut self) -> anyhow::Result<u32> {
        let mut new_tree = MerkleTree::new_for_depth(utils::TREE_DEPTH)?;
        let mut count = 0u32;
        let mut first_err: Option<anyhow::Error> = None;
        self.db.iterate_pool_leaves(|leaf| {
            let mut check = || -> anyhow::Result<()> {
                anyhow::ensure!(
                    leaf.index == new_tree.next_index,
                    "gap in leaf indices: expected {}, got {}",
                    new_tree.next_index,
                    leaf.index,
                );
                new_tree.insert(hex_to_scalar(&leaf.commitment)?)?;
                Ok(())
            };
            match check() {
                Ok(()) => {
                    count = count.saturating_add(1);
                    true
                }
                Err(e) => {
                    first_err = Some(e);
                    false
                }
            }
        })?;
        if let Some(e) = first_err {
            return Err(e);
        }
        self.tree = new_tree;
        Ok(count)
    }

    /// Persists a new commitment and inserts it into the in-memory tree.
    pub fn process_new_commitment(
        &mut self,
        commitment: &str,
        index: u32,
        encrypted_output: &str,
        ledger: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            index == self.tree.next_index,
            "out-of-order commitment: expected index {}, got {index}",
            self.tree.next_index,
        );
        let scalar = hex_to_scalar(commitment)?;
        self.db.put_pool_leaf(&PoolLeaf {
            index,
            commitment: commitment.to_owned(),
            ledger,
        })?;
        self.db.put_encrypted_output(&PoolEncryptedOutput {
            commitment: commitment.to_owned(),
            leaf_index: index,
            encrypted_output: encrypted_output.to_owned(),
            ledger,
        })?;
        self.tree.insert(scalar)?;
        Ok(())
    }

    /// Persists a spent nullifier.
    pub fn process_new_nullifier(&mut self, nullifier: &str, ledger: u32) -> anyhow::Result<()> {
        self.db.put_nullifier(&PoolNullifier {
            nullifier: nullifier.to_owned(),
            ledger,
        })
    }

    /// Returns the tree root as LE bytes.
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// Returns the tree root as a `0x`-prefixed big-endian hex string.
    pub fn root_hex(&self) -> String {
        let mut be = self.tree.root();
        be.reverse();
        bytes_to_hex(&be)
    }

    /// Returns the Merkle proof for `leaf_index`.
    pub fn get_proof(&self, leaf_index: u32) -> anyhow::Result<MerkleProof> {
        self.tree.get_proof(leaf_index)
    }

    /// Returns the nullifier record if it has been spent, or `None`.
    pub fn get_nullifier(&self, nullifier: &str) -> anyhow::Result<Option<PoolNullifier>> {
        self.db.get_nullifier(nullifier)
    }

    /// Returns encrypted outputs, optionally filtered to `ledger >=
    /// from_ledger`.
    pub fn get_encrypted_outputs(
        &self,
        from_ledger: Option<u32>,
    ) -> anyhow::Result<Vec<PoolEncryptedOutput>> {
        match from_ledger {
            Some(from) => self.db.get_encrypted_outputs_from(from),
            None => self.db.get_all_encrypted_outputs(),
        }
    }

    /// Returns the number of pool leaves in the database.
    pub fn leaf_count(&self) -> anyhow::Result<u32> {
        self.db.count_pool_leaves()
    }

    /// Returns the next insertion index.
    pub fn next_index(&self) -> u32 {
        self.tree.next_index
    }

    /// Clears all pool data and resets the in-memory tree.
    pub fn clear(&mut self) -> anyhow::Result<()> {
        self.db.clear_pool_leaves()?;
        self.db.clear_nullifiers()?;
        self.db.clear_encrypted_outputs()?;
        self.tree = MerkleTree::new_for_depth(utils::TREE_DEPTH)?;
        Ok(())
    }
}
