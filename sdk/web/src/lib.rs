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
pub use events::bootnode_required_js as bootnode_required;
pub use storage::Storage;

pub(crate) fn wasm_start() {
    console_error_panic_hook::set_once();
    static LOG: std::sync::Once = std::sync::Once::new();
    LOG.call_once(|| {
        wasm_log::init(wasm_log::Config::default());
    });
}
