//! Browser SDK — wasm-bindgen bindings over [`stellar_private_payments_sdk`].
//!
//! Connect with [`Client`], then [`Client::account`], then [`Account::pool`].

mod circuits;
mod client;
mod deployment;
mod events;
mod protocol;
mod signer;
mod storage;
pub mod workers;

pub(crate) mod artifact_hashes {
    include!(concat!(env!("OUT_DIR"), "/artifact_hashes.rs"));
}

pub(crate) const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

pub use client::{Account, Client, PrivatePool, verify_selective_disclosure_standalone};
pub use storage::Storage;

pub(crate) fn wasm_start() {
    console_error_panic_hook::set_once();
}
