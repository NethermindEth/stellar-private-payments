//! Prover WASM Module
//!
//! This module provides browser-compatible ZK proof generation using Groth16.
//! It handles:
//! - Input preparation (cryptographic operations, merkle trees)
//! - Proof generation from witness data
//!
//! # Architecture
//! This module receives witness data (Uint8Array) from the witness
//! module via pure data exchange

#![no_std]
extern crate alloc;

pub mod crypto;
pub mod encryption;
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
