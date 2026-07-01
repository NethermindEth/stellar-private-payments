//! Browser SDK — wasm-bindgen bindings over [`stellar_private_payments_sdk`].
//!
//! Connect with [`Client`], then open per-pool sessions via [`Client::pool`].

mod amounts;
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

pub use client::{Client, PrivatePool};
pub use storage::Storage;

pub(crate) fn wasm_start() {
    console_error_panic_hook::set_once();
}
