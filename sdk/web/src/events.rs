//! Browser sync helpers: bootnode probe for wallet RPC retention.

use stellar_private_payments_sdk::{
    Storage,
    chain::{Indexer, RpcClient, RpcError},
    types::ContractConfig,
};
use wasm_bindgen::prelude::*;

use crate::{
    deployment::deployment_config, storage::Storage as WasmStorage, workers::storage::StorageBridge,
};

pub(crate) fn is_rpc_sync_gap(err: &anyhow::Error) -> bool {
    matches!(
        err.downcast_ref::<RpcError>(),
        Some(RpcError::RpcSyncGap(_))
    )
}

/// Probes wallet RPC retention. Returns `true` when a bootnode is required
/// (sync gap), `false` when the wallet RPC can serve history.
pub(crate) async fn bootnode_required(
    rpc: &RpcClient,
    storage: StorageBridge,
    config: &'static ContractConfig,
) -> Result<bool, anyhow::Error> {
    log::info!("bootnodeRequired: probing wallet RPC retention");
    match Indexer::init(
        rpc.clone(),
        storage.fork().map_err(anyhow::Error::msg)?,
        config,
    )
    .await
    {
        Ok(_) => {
            log::info!("bootnodeRequired: false (wallet RPC has history)");
            Ok(false)
        }
        Err(e) if is_rpc_sync_gap(&e) => {
            log::warn!("bootnodeRequired: true (RPC sync gap: {e:#})");
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Probe whether the wallet RPC needs a historical-sync bootnode.
///
/// Does not take or resolve a bootnode URL — callers supply that via
/// [`crate::Client::new`] after checking storage / prompting the user.
#[wasm_bindgen(js_name = bootnodeRequired)]
pub async fn bootnode_required_js(rpc_url: String, storage: &WasmStorage) -> Result<bool, JsError> {
    crate::wasm_start();
    let rpc = RpcClient::new(&rpc_url).map_err(|e| JsError::new(&format!("rpc error: {e:#}")))?;
    let config = deployment_config()?;
    bootnode_required(&rpc, storage.bridge(), config)
        .await
        .map_err(|e| JsError::new(&e.to_string()))
}
