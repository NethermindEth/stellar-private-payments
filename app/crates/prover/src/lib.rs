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
