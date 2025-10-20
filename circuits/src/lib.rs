//! Build script crate.
//!
//! This crate exists solely to run the build script in `build.rs`.
//! No public API is provided.
/// Test modules for circuit testing
pub mod test {
    /// Sparse Merkle Tree implementation and tests
    pub mod utils {
        pub mod sparse_merkle_tree;
    }
}
