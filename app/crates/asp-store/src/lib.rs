//! In-memory Poseidon2 Merkle tree with SQLite-backed ASP membership state.
//! Port of `app/js/state/asp-membership-store.js`.
//! Leaves must arrive in strict ascending index order.

use storage::{Storage, types::AspMembershipLeaf};
use utils::{
    bytes_to_hex,
    merkle::{MerkleProof, MerkleTree, hex_to_scalar},
};

/// ASP membership state: in-memory Poseidon2 Merkle tree with SQLite-backed
/// persistence. Leaves must arrive in strict ascending index order.
pub struct AspStore {
    db: Storage,
    tree: MerkleTree,
}

impl AspStore {
    /// Opens the ASP store and rebuilds the in-memory tree from `db`.
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
        self.db.iterate_asp_membership_leaves(|leaf| {
            let mut check = || -> anyhow::Result<()> {
                anyhow::ensure!(
                    leaf.index == new_tree.next_index,
                    "gap in leaf indices: expected {}, got {}",
                    new_tree.next_index,
                    leaf.index,
                );
                new_tree.insert(hex_to_scalar(&leaf.leaf)?)?;
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

    /// Persists a new ASP membership leaf. Errors if `index` is out of order.
    pub fn process_leaf_added(
        &mut self,
        leaf: &str,
        index: u32,
        root: &str,
        ledger: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            index == self.tree.next_index,
            "out-of-order insertion: expected index {}, got {index}",
            self.tree.next_index,
        );
        let scalar = hex_to_scalar(leaf)?;
        self.tree.insert(scalar)?;
        self.db.put_asp_membership_leaf(&AspMembershipLeaf {
            index,
            leaf: leaf.to_owned(),
            root: root.to_owned(),
            ledger,
        })?;
        Ok(())
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

    /// Returns the leaf record for `leaf_hash`, or `None` if not found.
    pub fn find_leaf_by_hash(&self, leaf_hash: &str) -> anyhow::Result<Option<AspMembershipLeaf>> {
        self.db.get_asp_membership_leaf_by_hash(leaf_hash)
    }

    /// Returns the number of ASP membership leaves in the database.
    pub fn leaf_count(&self) -> anyhow::Result<u32> {
        self.db.count_asp_membership_leaves()
    }

    /// Returns the next insertion index.
    pub fn next_index(&self) -> u32 {
        self.tree.next_index
    }

    /// Clears all ASP membership data and resets the in-memory tree.
    pub fn clear(&mut self) -> anyhow::Result<()> {
        self.db.clear_asp_membership_leaves()?;
        self.tree = MerkleTree::new_for_depth(utils::TREE_DEPTH)?;
        Ok(())
    }
}
