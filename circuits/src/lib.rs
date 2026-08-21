//! Circuits crate
//!
//! Circom sources live under `src/**/*.circom`. Artifact compilation is
//! `tools/circuit-compiler`.
//!
//! The `core` module is always available and `no_std` compatible (for frontend
//! WASM compatibility).

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

/// Core circuit utilities
pub mod core;

/// Test utilities (requires std for file I/O)
#[cfg(feature = "std")]
pub mod test;
