//! Build script crate.
//!
//! This crate exists solely to run the build script in `build.rs`.
//! No public API is provided.

// Test utilities depend on heavy circom tooling; only compile when explicitly
// enabled.
#[cfg(feature = "circom-tests")]
pub mod test;
