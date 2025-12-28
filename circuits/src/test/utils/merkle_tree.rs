use zkhash::fields::bn256::FpBN256 as Scalar;

use super::general::poseidon2_compression;

/// Compute the Merkle parent from ordered children (left, right)
///
/// Uses Poseidon2 compression to combine two child nodes into a parent node.
///
/// # Arguments
///
/// * `left` - Left child node scalar value
/// * `right` - Right child node scalar value
///
/// # Returns
///
/// Returns the parent node scalar value.
#[inline]
pub fn merkle_parent(left: Scalar, right: Scalar) -> Scalar {
    poseidon2_compression(left, right)
}

/// Build a Merkle root from a full list of leaves
///
/// Computes the Merkle root by repeatedly hashing pairs of nodes until
/// a single root remains.
///
/// # Arguments
///
/// * `leaves` - Vector of leaf scalar values (length must be a power of 2)
///
/// # Returns
///
/// Returns the computed Merkle root scalar value.
pub fn merkle_root(mut leaves: Vec<Scalar>) -> Scalar {
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(poseidon2_compression(pair[0], pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}

/// Compute the Merkle path (siblings) and path index bits for a given leaf
/// index
///
/// Generates the Merkle proof for a leaf at the given index, including all
/// sibling nodes along the path to the root and the path indices encoded as
/// a bit pattern.
///
/// # Arguments
///
/// * `leaves` - Array of leaf scalar values (length must be a power of 2)
/// * `index` - Index of the leaf to generate a proof for
///
/// # Returns
///
/// Returns a tuple containing:
/// - `path_elements`: Vector of sibling scalar values along the path
/// - `path_indices`: Path indices encoded as a u64 bit pattern
/// - `levels`: Number of levels in the tree
pub fn merkle_proof(leaves: &[Scalar], mut index: usize) -> (Vec<Scalar>, u64, usize) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level_nodes = leaves.to_vec();
    let levels = level_nodes.len().ilog2() as usize;

    let mut path_elems = Vec::with_capacity(levels);
    let mut path_indices_bits_lsb = Vec::with_capacity(levels);

    for _level in 0..levels {
        let sib_index = if index.is_multiple_of(2) {
            index.checked_add(1).expect("sibling index overflow")
        } else {
            index.checked_sub(1).expect("sibling index underflow")
        };

        path_elems.push(level_nodes[sib_index]);
        path_indices_bits_lsb.push((index & 1) as u64);

        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in level_nodes.chunks_exact(2) {
            next.push(merkle_parent(pair[0], pair[1]));
        }
        level_nodes = next;
        index /= 2;
    }

    let mut path_indices: u64 = 0;

    for (i, b) in path_indices_bits_lsb.iter().copied().enumerate() {
        path_indices |= b << i;
    }

    (path_elems, path_indices, levels)
}
