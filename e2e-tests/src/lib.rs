//! End-to-End Tests for Privacy Pool
//!
//! This crate bridges the gap between:
//! - The `circuits` crate that generates Groth16 proofs (and it employs std)
//! - The `contracts` crate with the Pool contract that verifies the proofs (and it doesn't employ std)

#[cfg(test)]
mod tests;
