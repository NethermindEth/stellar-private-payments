//! Infrastructure shared by the `pool` and `pool-gvk` contracts.
//!
//! Soroban ties `#[contractimpl]` methods to a single `#[contract]` struct and
//! emits them as `#[no_mangle] extern "C"` exports that the linker never
//! dead-code-eliminates. Two contract crates therefore cannot depend on each
//! other for *any* item without dragging in each other's exports and colliding
//! on identically-named methods. This crate holds the parts that carry no
//! exports — the Merkle tree, policy flags, external-transaction data, and the
//! cross-contract client traits — so both contracts can share one copy.
//!
//! Nothing here may declare `#[contract]` or `#[contractimpl]`.

#![no_std]

pub mod amounts;
pub mod clients;
pub mod ext_data;
pub mod merkle_with_history;
pub mod policy;

pub use clients::{
    ASPMembershipClient, ASPMembershipInterface, ASPNonMembershipClient, ASPNonMembershipInterface,
    CircomGroth16VerifierClient, CircomGroth16VerifierInterface,
};
pub use ext_data::{ExtData, hash_ext_data};
