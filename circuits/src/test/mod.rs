//! Test utilities for circuit proving and verification.
//!
//! This module is only compiled when the `circom-tests` feature is enabled.

#![allow(missing_docs)]
#![allow(dead_code)]

mod prove_merkle;
mod prove_poseidon2;
mod prove_sparse;

mod prove_compliance;
mod prove_keypair;
mod prove_transaction;
pub mod utils;

use utils::{circom_tester, keypair, merkle_tree};
