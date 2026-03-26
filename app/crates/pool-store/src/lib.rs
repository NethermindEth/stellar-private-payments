//! In-memory Poseidon2 Merkle tree with SQLite-backed pool state.
//! Port of `app/js/state/pool-store.js`.

use ark_ff::PrimeField as _;
use circuits::core::merkle::poseidon2_compression;
use zkhash::fields::bn256::FpBN256 as Scalar;

use storage::{
    Storage,
    types::{PoolEncryptedOutput, PoolLeaf, PoolNullifier},
};
use utils::{bytes_to_hex, hex_to_bytes_for_tree};

/// Byte length of a BN254 field element.
const FIELD_SIZE: usize = 32;

/// Poseidon2("XLM") as big-endian bytes; the pool contract's zero-leaf
/// sentinel.
const ZERO_LEAF_BE: [u8; FIELD_SIZE] = [
    37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187, 158, 240,
    248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Merkle membership proof for a pool leaf.
pub struct MerkleProof {
    /// Sibling hashes from leaf to root (LE bytes, `TREE_DEPTH × FIELD_SIZE`).
    pub path_elements: Vec<u8>,
    /// Direction bits: bit `i` set when node at level `i` is a right child.
    pub path_indices: u64,
    /// Tree root at proof time, as LE bytes.
    pub root: [u8; FIELD_SIZE],
}

// ---------------------------------------------------------------------------
// Internal Merkle tree
// ---------------------------------------------------------------------------

struct MerkleTree {
    /// `levels[0]` = leaf layer; `levels[depth]` = single root node.
    levels: Vec<Vec<Scalar>>,
    depth: usize,
    next_index: u32,
}

impl MerkleTree {
    fn new(depth: usize, zero: Scalar) -> anyhow::Result<Self> {
        anyhow::ensure!(depth > 0 && depth <= 20, "tree depth must be 1–20");

        let num_leaves = 1usize
            .checked_shl(u32::try_from(depth).expect("depth fits u32"))
            .ok_or_else(|| anyhow::anyhow!("depth overflow"))?;

        let mut levels = Vec::with_capacity(depth.saturating_add(1));
        levels.push(vec![zero; num_leaves]);

        let mut prev = zero;
        let mut width = num_leaves;
        for _ in 0..depth {
            width /= 2;
            prev = poseidon2_compression(prev, prev);
            levels.push(vec![prev; width]);
        }

        Ok(Self {
            levels,
            depth,
            next_index: 0,
        })
    }

    fn insert(&mut self, leaf: Scalar) -> anyhow::Result<u32> {
        let max = u32::try_from(1usize << self.depth).unwrap_or(u32::MAX);
        anyhow::ensure!(self.next_index < max, "Merkle tree is full");

        let idx = usize::try_from(self.next_index).expect("index fits usize");
        self.levels[0][idx] = leaf;

        let mut cur_idx = idx;
        let mut cur_hash = leaf;
        for level in 0..self.depth {
            let sib = self.levels[level][cur_idx ^ 1];
            let (left, right) = if cur_idx.is_multiple_of(2) {
                (cur_hash, sib)
            } else {
                (sib, cur_hash)
            };
            cur_hash = poseidon2_compression(left, right);
            cur_idx /= 2;
            self.levels[level.saturating_add(1)][cur_idx] = cur_hash;
        }

        let inserted = self.next_index;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("index overflow"))?;
        Ok(inserted)
    }

    fn root(&self) -> [u8; FIELD_SIZE] {
        scalar_to_array(&self.levels[self.depth][0])
    }

    fn get_proof(&self, leaf_index: u32) -> anyhow::Result<MerkleProof> {
        anyhow::ensure!(leaf_index < self.next_index, "leaf index out of range");

        let mut cur_idx = usize::try_from(leaf_index).expect("index fits usize");
        let cap = self
            .depth
            .checked_mul(FIELD_SIZE)
            .ok_or_else(|| anyhow::anyhow!("path capacity overflow"))?;
        let mut path_elements = Vec::with_capacity(cap);
        let mut path_indices: u64 = 0;

        for level in 0..self.depth {
            let sib = self.levels[level][cur_idx ^ 1];
            path_elements.extend_from_slice(&scalar_to_array(&sib));
            if !cur_idx.is_multiple_of(2) {
                path_indices |= 1u64 << level;
            }
            cur_idx /= 2;
        }

        Ok(MerkleProof {
            path_elements,
            path_indices,
            root: self.root(),
        })
    }
}

// ---------------------------------------------------------------------------
// PoolStore
// ---------------------------------------------------------------------------

/// Pool state: in-memory Poseidon2 Merkle tree with SQLite-backed persistence.
pub struct PoolStore {
    db: Storage,
    tree: MerkleTree,
}

impl PoolStore {
    /// Opens the pool store and rebuilds the in-memory tree from `db`.
    pub fn open(db: Storage) -> anyhow::Result<Self> {
        let tree = fresh_tree()?;
        let mut store = Self { db, tree };
        store.rebuild_tree()?;
        Ok(store)
    }

    /// Rebuilds the in-memory tree from persisted leaves. Returns the leaf
    /// count.
    pub fn rebuild_tree(&mut self) -> anyhow::Result<u32> {
        let mut new_tree = fresh_tree()?;
        let mut count = 0u32;
        let mut first_err: Option<anyhow::Error> = None;
        self.db.iterate_pool_leaves(|leaf| {
            match hex_to_scalar(&leaf.commitment).and_then(|s| new_tree.insert(s).map(|_| ())) {
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
        // Decode before writing to DB so invalid hex never reaches storage.
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
    pub fn root(&self) -> [u8; FIELD_SIZE] {
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
        self.tree = fresh_tree()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fresh_tree() -> anyhow::Result<MerkleTree> {
    let mut zero_le = ZERO_LEAF_BE;
    zero_le.reverse();
    let zero = Scalar::from_le_bytes_mod_order(&zero_le);
    MerkleTree::new(utils::TREE_DEPTH, zero)
}

fn hex_to_scalar(commitment: &str) -> anyhow::Result<Scalar> {
    let le = hex_to_bytes_for_tree(commitment)
        .map_err(|e| anyhow::anyhow!("invalid commitment hex: {e}"))?;
    anyhow::ensure!(
        le.len() == FIELD_SIZE,
        "commitment must be {FIELD_SIZE} bytes"
    );
    Ok(Scalar::from_le_bytes_mod_order(&le))
}

fn scalar_to_array(s: &Scalar) -> [u8; FIELD_SIZE] {
    let mut out = [0u8; FIELD_SIZE];
    let bigint = s.into_bigint();
    for (i, limb) in bigint.0.iter().enumerate() {
        let start = i.saturating_mul(8);
        let end = start.saturating_add(8).min(FIELD_SIZE);
        out[start..end].copy_from_slice(&limb.to_le_bytes()[..end.saturating_sub(start)]);
    }
    out
}
