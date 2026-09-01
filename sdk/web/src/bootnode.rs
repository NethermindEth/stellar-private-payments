//! Wasm binding for the native bootnode retention probe.

use stellar_private_payments::{bootnode_required, chain::RpcClient};
use wasm_bindgen::prelude::*;

use crate::{deployment::parse_contract_config, storage::Storage as WasmStorage};

/// Probe whether the wallet RPC needs a historical-sync bootnode.
///
/// Does not take or resolve a bootnode URL — callers supply that via
/// [`crate::Client::new`] after checking storage / prompting the user.
#[wasm_bindgen(js_name = bootnodeRequired)]
pub async fn bootnode_required_js(
    rpc_url: String,
    storage: &WasmStorage,
    contract_config: JsValue,
) -> Result<bool, JsError> {
    crate::wasm_start();
    let rpc = RpcClient::new(&rpc_url).map_err(|e| JsError::new(&format!("rpc error: {e:#}")))?;
    let config = parse_contract_config(contract_config)?;
    bootnode_required(&rpc, &storage.bridge(), &config)
        .await
        .map_err(|e| JsError::new(&e.to_string()))
}
