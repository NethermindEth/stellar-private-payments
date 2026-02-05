//! Circuits crate
//!
//! Provides core utilities for ZK circuits and test tooling.
//!
//! The `core` module is always available and `no_std` compatible (for frontend
//! WASM compatibility). The `test` module is available with the `circom-tests`
//! feature or during test compilation.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// Core circuit utilities
pub mod core;

/// Test utilities
#[cfg(any(test, feature = "circom-tests"))]
pub mod test;
