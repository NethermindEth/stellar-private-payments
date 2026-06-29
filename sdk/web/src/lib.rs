//! Browser SDK — wasm-bindgen bindings over [`stellar_private_payments_sdk`].
//!
//! The main entry point is [`PrivatePool`] (exported to JS as `PrivatePool`).
//! Published as the `private-payments-sdk` npm package from this crate
//! directory.

mod amounts;
mod client;
mod protocol;
mod signer;
pub mod workers;

pub(crate) mod artifact_hashes {
    include!(concat!(env!("OUT_DIR"), "/artifact_hashes.rs"));
}

pub(crate) const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

use wasm_bindgen::prelude::*;

pub use client::{PrivatePool, SdkClient, SdkConfig};

#[wasm_bindgen(start)]
pub fn wasm_start() {
    console_error_panic_hook::set_once();
}
