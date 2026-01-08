//! Circuits crate
//!
//! Provides core utilities for ZK circuits and test tooling.
//!
//! The `core` module is always available and `no_std` compatible (for frontend
//! WASM compatibility). The `test` module requires the `circom-tests` feature.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// Core circuit utilities
pub mod core;

/// Test utilities
#[cfg(feature = "circom-tests")]
pub mod test;
