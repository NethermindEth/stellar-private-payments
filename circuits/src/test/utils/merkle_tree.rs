//! Merkle tree utilities for circuit testing
//!
//! Re-exports core merkle functions from `crate::core::merkle`.

pub use crate::core::merkle::{
    PrefixTree, merkle_proof, merkle_proof_padded, merkle_root, merkle_root_padded, zero_leaf,
};
