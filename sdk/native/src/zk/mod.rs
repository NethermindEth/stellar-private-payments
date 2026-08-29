//! Zero-knowledge proving stack: circuit crypto, Groth16, witness generation,
//! and selective-disclosure receipt validation.

pub mod babyjub;
pub mod circom_reduction;
pub mod crypto;
pub mod disclosure;
pub mod encryption;
pub mod flows;
pub mod gvk;
pub mod merkle;
pub mod notes;
pub mod prover;
pub mod r1cs;
pub mod serialization;
pub mod sparse_merkle;
pub mod types;
pub mod witness;
