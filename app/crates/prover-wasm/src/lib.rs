//! Prover WASM Module (Apache-2.0)
//!
//! This module provides browser-compatible ZK proof generation using Groth16.
//! It handles:
//! - Input preparation (crypto operations, merkle trees)
//! - Proof generation from witness data
//!
//! # License
//! Apache-2.0 - No GPL code is linked or included.
//!
//! # Architecture
//! This module receives witness data (Uint8Array) from the GPL-3.0 witness module
//! via pure data exchange, ensuring license isolation.

#![no_std]
extern crate alloc;

pub mod crypto;
pub mod merkle;
pub mod prover;
pub mod r1cs;
pub mod serialization;
pub mod sparse_merkle;
pub mod types;

use wasm_bindgen::prelude::*;

/// Initialize the WASM module
/// Sets up panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Get the module version
#[wasm_bindgen]
pub fn version() -> alloc::string::String {
    alloc::string::String::from(env!("CARGO_PKG_VERSION"))
}

