use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_2},
};

/// Poseidon2 hash of two field elements (t = 2), returning the first lane
/// (state[0]).
pub fn poseidon2_hash2(left: Scalar, right: Scalar) -> Scalar {
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_2);
    let out = h.permutation(&[left, right]);
    out[0]
}

/// Compute the Merkle parent from ordered children (left, right).
#[inline]
pub fn merkle_parent(left: Scalar, right: Scalar) -> Scalar {
    poseidon2_hash2(left, right)
}

/// Build a Merkle root from a full list of leaves (length must be a power of
/// 2).
pub fn merkle_root(mut leaves: Vec<Scalar>) -> Scalar {
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks_exact(2) {
            next.push(poseidon2_hash2(pair[0], pair[1]));
        }
        leaves = next;
    }
    leaves[0]
}

/// Compute the Merkle path (siblings) and path index bits (LSB-first) for a
/// given leaf index. Returns (path_elements, path_indices, levels).
pub fn merkle_proof(leaves: &[Scalar], mut index: usize) -> (Vec<Scalar>, u64, usize) {
    assert!(!leaves.is_empty() && leaves.len().is_power_of_two());
    let mut level_nodes = leaves.to_vec();
    let levels = level_nodes.len().ilog2() as usize;

    let mut path_elems = Vec::with_capacity(levels);
    let mut path_indices_bits_lsb = Vec::with_capacity(levels);

    for _level in 0..levels {
        let sib_index = if index % 2 == 0 {
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
