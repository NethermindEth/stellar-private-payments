//! Browser SDK — wasm-bindgen bindings over [`stellar_private_payments_sdk`].
//!
//! Connect with [`Client`], then open per-pool sessions via [`Client::pool`].

mod amounts;
mod client;
mod deployment;
mod protocol;
mod signer;
mod storage;
pub mod workers;

pub(crate) mod artifact_hashes {
    include!(concat!(env!("OUT_DIR"), "/artifact_hashes.rs"));
}

pub(crate) const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

use wasm_bindgen::prelude::*;

pub use client::{Client, PrivatePool};
pub use storage::Storage;

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}
