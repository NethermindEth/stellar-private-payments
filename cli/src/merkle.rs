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

/// Build pool leaves array from database.
///
/// Returns a vector of length `POOL_TREE_SIZE` with commitments placed at their
/// indices (zero-filled for empty slots).
pub fn build_pool_leaves(db: &Database) -> Result<Vec<Scalar>> {
    let mut leaves = vec![Scalar::from(0u64); POOL_TREE_SIZE];
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
    let mut leaves = vec![Scalar::from(0u64); ASP_TREE_SIZE];
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
