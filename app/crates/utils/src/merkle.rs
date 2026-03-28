//! Poseidon2 Merkle tree shared by pool-store and asp-store.

use ark_ff::PrimeField as _;
use circuits::core::merkle::poseidon2_compression;
use zkhash::fields::bn256::FpBN256 as Scalar;

/// Byte length of a BN254 field element.
pub const FIELD_SIZE: usize = 32;

/// Poseidon2("XLM") as big-endian bytes; the contract zero-leaf sentinel.
pub const ZERO_LEAF_BE: [u8; FIELD_SIZE] = [
    37, 48, 34, 136, 219, 153, 53, 3, 68, 151, 65, 131, 206, 49, 13, 99, 181, 58, 187, 158, 240,
    248, 87, 87, 83, 238, 211, 110, 1, 24, 249, 206,
];

/// Merkle membership proof.
pub struct MerkleProof {
    /// Sibling hashes from leaf to root (LE bytes, `depth × FIELD_SIZE`).
    pub path_elements: Vec<u8>,
    /// Direction bits: bit `i` set when node at level `i` is a right child.
    pub path_indices: u64,
    /// Tree root at proof time, as LE bytes.
    pub root: [u8; FIELD_SIZE],
}

/// In-memory Poseidon2 Merkle tree.
pub struct MerkleTree {
    levels: Vec<Vec<Scalar>>,
    depth: usize,
    /// Next leaf insertion index.
    pub next_index: u32,
}

impl MerkleTree {
    /// Creates a tree of `depth` filled with the default zero leaf.
    pub fn new_for_depth(depth: usize) -> anyhow::Result<Self> {
        let mut zero_le = ZERO_LEAF_BE;
        zero_le.reverse();
        let zero = Scalar::from_le_bytes_mod_order(&zero_le);
        Self::new(depth, zero)
    }

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

    /// Inserts a leaf at `next_index` and rehashes up to root.
    pub fn insert(&mut self, leaf: Scalar) -> anyhow::Result<u32> {
        let max = u32::try_from(1usize << self.depth).map_err(|_| {
            anyhow::anyhow!("tree depth {d} overflows u32 capacity", d = self.depth)
        })?;
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

    /// Returns the current root as LE bytes.
    pub fn root(&self) -> [u8; FIELD_SIZE] {
        scalar_to_array(&self.levels[self.depth][0])
    }

    /// Returns a Merkle proof for the leaf at `leaf_index`.
    pub fn get_proof(&self, leaf_index: u32) -> anyhow::Result<MerkleProof> {
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

/// Converts a BN254 scalar to a 32-byte LE array.
pub fn scalar_to_array(s: &Scalar) -> [u8; FIELD_SIZE] {
    let mut out = [0u8; FIELD_SIZE];
    let bigint = s.into_bigint();
    for (i, limb) in bigint.0.iter().enumerate() {
        let start = i.saturating_mul(8);
        let end = start.saturating_add(8).min(FIELD_SIZE);
        out[start..end].copy_from_slice(&limb.to_le_bytes()[..end.saturating_sub(start)]);
    }
    out
}

/// Converts LE bytes to a BN254 scalar.
pub fn le_bytes_to_scalar(bytes: &[u8]) -> anyhow::Result<Scalar> {
    anyhow::ensure!(bytes.len() == FIELD_SIZE, "expected {FIELD_SIZE} bytes");
    Ok(Scalar::from_le_bytes_mod_order(bytes))
}

/// Decodes a BE hex string to a BN254 scalar (via LE conversion).
pub fn hex_to_scalar(s: &str) -> anyhow::Result<Scalar> {
    let le = crate::hex_to_bytes_for_tree(s).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;
    anyhow::ensure!(le.len() == FIELD_SIZE, "expected {FIELD_SIZE} bytes");
    Ok(Scalar::from_le_bytes_mod_order(&le))
}
