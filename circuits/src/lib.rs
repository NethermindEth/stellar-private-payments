//! Build script crate.
//!
//! This crate exists solely to run the build script in `build.rs`.
//! No public API is provided.

// Tests depend on heavy circom tooling; only compile them when explicitly enabled.
#[cfg(all(test, feature = "circom-tests"))]
mod test;
