//! In-memory pool + ASP Merkle trees.
//!
//! Reconstructed from SQLite on demand.

use anyhow::{Result, bail};
use zkhash::fields::bn256::FpBN256 as Scalar;

use crate::crypto;
use crate::db::Database;

/// Number of levels in the pool's commitment Merkle tree.
pub const POOL_LEVELS: usize = 10;

/// Number of levels in the ASP membership Merkle tree.
pub const ASP_LEVELS: usize = 10;

/// Pool tree size (2^POOL_LEVELS).
pub const POOL_TREE_SIZE: usize = 1 << POOL_LEVELS;

/// ASP tree size (2^ASP_LEVELS).
pub const ASP_TREE_SIZE: usize = 1 << ASP_LEVELS;

/// The default ("zero") leaf value used by on-chain Merkle trees.
///
/// Computed as `Poseidon2("XLM")` = `poseidon2_hash3(88, 76, 77, domain=0)`.
/// This must match `get_zeroes()[0]` in `contracts/soroban-utils/src/poseidon2.rs`.
pub fn zero_leaf() -> Scalar {
    crypto::poseidon2_hash3(
        Scalar::from(88u64),  // 'X'
        Scalar::from(76u64),  // 'L'
        Scalar::from(77u64),  // 'M'
        None,                 // domain = 0
    )
}

/// Build pool leaves array from database.
///
/// Returns a vector of length `POOL_TREE_SIZE` with commitments placed at their
/// indices. Empty slots are filled with [`zero_leaf()`] to match the on-chain
/// Merkle tree default.
pub fn build_pool_leaves(db: &Database) -> Result<Vec<Scalar>> {
    let zero = zero_leaf();
    let mut leaves = vec![zero; POOL_TREE_SIZE];
    let db_leaves = db.get_pool_leaves()?;

    for (idx, commitment_hex) in &db_leaves {
        let idx_usize = usize::try_from(*idx).map_err(|_| anyhow::anyhow!("index overflow"))?;
        if idx_usize >= POOL_TREE_SIZE {
            bail!("Pool leaf index {idx_usize} exceeds tree size {POOL_TREE_SIZE}");
        }
        leaves[idx_usize] = crypto::hex_be_to_scalar(commitment_hex)?;
    }

    Ok(leaves)
}

/// Build ASP membership leaves array from database.
pub fn build_asp_leaves(db: &Database) -> Result<Vec<Scalar>> {
    let zero = zero_leaf();
    let mut leaves = vec![zero; ASP_TREE_SIZE];
    let db_leaves = db.get_asp_leaves()?;

    for (idx, leaf_hex) in &db_leaves {
        let idx_usize = usize::try_from(*idx).map_err(|_| anyhow::anyhow!("index overflow"))?;
        if idx_usize >= ASP_TREE_SIZE {
            bail!("ASP leaf index {idx_usize} exceeds tree size {ASP_TREE_SIZE}");
        }
        leaves[idx_usize] = crypto::hex_be_to_scalar(leaf_hex)?;
    }

    Ok(leaves)
}

/// Compute the Merkle root of a list of leaves.
pub fn merkle_root(leaves: &[Scalar]) -> Scalar {
    circuits::core::merkle::merkle_root(leaves.to_vec())
}

/// Compute a Merkle proof for a leaf at the given index.
///
/// Returns `(path_elements, path_indices_u64, depth)`.
pub fn merkle_proof(leaves: &[Scalar], index: usize) -> (Vec<Scalar>, u64, usize) {
    circuits::core::merkle::merkle_proof(leaves, index)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::db::Database;

    fn test_db() -> Database {
        Database::open_in_memory().expect("in-memory DB")
    }

    // ========== Merkle root/proof ==========

    #[test]
    fn test_merkle_root_deterministic() {
        let leaves = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64), Scalar::from(4u64)];
        let root1 = merkle_root(&leaves);
        let root2 = merkle_root(&leaves);
        assert_eq!(root1, root2, "merkle root should be deterministic");
    }

    #[test]
    fn test_merkle_root_changes_with_different_leaves() {
        let leaves1 = vec![Scalar::from(1u64); 4];
        let leaves2 = vec![Scalar::from(2u64); 4];
        assert_ne!(
            merkle_root(&leaves1),
            merkle_root(&leaves2),
            "different leaves should produce different roots"
        );
    }

    #[test]
    fn test_merkle_proof_index_0() {
        let leaves = vec![Scalar::from(10u64), Scalar::from(20u64), Scalar::from(30u64), Scalar::from(40u64)];
        let (siblings, path_indices, depth) = merkle_proof(&leaves, 0);

        assert!(!siblings.is_empty(), "siblings should not be empty");
        assert!(depth > 0, "depth should be > 0");
        // path_indices for index 0 should encode 0 in all bits
        assert_eq!(path_indices, 0);
    }

    #[test]
    fn test_merkle_proof_verifies() {
        // Build a small tree, take a proof, and manually reconstruct root
        let leaves = vec![Scalar::from(100u64), Scalar::from(200u64), Scalar::from(0u64), Scalar::from(0u64)];
        let root = merkle_root(&leaves);

        let (siblings, path_idx, _depth) = merkle_proof(&leaves, 0);

        // Reconstruct: walk up from leaf using siblings
        let mut current = leaves[0];
        let mut idx = path_idx;
        for sib in &siblings {
            if idx & 1 == 0 {
                current = crypto::poseidon2_compression(current, *sib);
            } else {
                current = crypto::poseidon2_compression(*sib, current);
            }
            idx >>= 1;
        }
        assert_eq!(current, root, "reconstructed root should match");
    }

    #[test]
    fn test_merkle_proof_index_1() {
        let leaves = vec![Scalar::from(10u64), Scalar::from(20u64), Scalar::from(0u64), Scalar::from(0u64)];
        let root = merkle_root(&leaves);

        let (siblings, path_idx, _depth) = merkle_proof(&leaves, 1);

        // Reconstruct from index 1
        let mut current = leaves[1];
        let mut idx = path_idx;
        for sib in &siblings {
            if idx & 1 == 0 {
                current = crypto::poseidon2_compression(current, *sib);
            } else {
                current = crypto::poseidon2_compression(*sib, current);
            }
            idx >>= 1;
        }
        assert_eq!(current, root, "proof from index 1 should reconstruct root");
    }

    // ========== build_pool_leaves / build_asp_leaves ==========

    #[test]
    fn test_build_pool_leaves_empty() {
        let db = test_db();
        let leaves = build_pool_leaves(&db).unwrap();
        assert_eq!(leaves.len(), POOL_TREE_SIZE);
        // All should be the default zero leaf
        let zero = zero_leaf();
        for leaf in &leaves {
            assert_eq!(*leaf, zero);
        }
    }

    #[test]
    fn test_build_pool_leaves_with_data() {
        let db = test_db();

        // Insert some leaves with valid hex commitment values
        let val = Scalar::from(42u64);
        let hex_str = crypto::scalar_to_hex_be(&val);
        db.insert_pool_leaf(0, &hex_str, 10).unwrap();

        let val2 = Scalar::from(99u64);
        let hex_str2 = crypto::scalar_to_hex_be(&val2);
        db.insert_pool_leaf(5, &hex_str2, 11).unwrap();

        let leaves = build_pool_leaves(&db).unwrap();
        assert_eq!(leaves[0], val);
        assert_eq!(leaves[5], val2);
        // Others should be the default zero leaf
        assert_eq!(leaves[1], zero_leaf());
    }

    #[test]
    fn test_build_pool_leaves_overflow() {
        let db = test_db();
        // Insert a leaf with index >= POOL_TREE_SIZE
        db.insert_pool_leaf(POOL_TREE_SIZE as u64, "ff", 1).unwrap();
        let result = build_pool_leaves(&db);
        assert!(result.is_err(), "should error on out-of-bounds index");
    }

    #[test]
    fn test_build_asp_leaves_empty() {
        let db = test_db();
        let leaves = build_asp_leaves(&db).unwrap();
        assert_eq!(leaves.len(), ASP_TREE_SIZE);
    }

    #[test]
    fn test_build_asp_leaves_with_data() {
        let db = test_db();
        let val = Scalar::from(7u64);
        let hex_str = crypto::scalar_to_hex_be(&val);
        db.insert_asp_leaf(2, &hex_str, 100).unwrap();

        let leaves = build_asp_leaves(&db).unwrap();
        assert_eq!(leaves[2], val);
        assert_eq!(leaves[0], zero_leaf());
    }
}
