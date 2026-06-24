//! Blocking bridge for async Stellar RPC calls from the sync pool API.

#![cfg(not(target_arch = "wasm32"))]

use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub(crate) fn block_on_rpc<F: std::future::Future>(future: F) -> F::Output {
    let rt = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for RPC")
    });
    rt.block_on(future)
}
