mod client;
mod config;
mod events;
mod protocol;
pub mod workers;

pub(crate) mod artifact_hashes {
    include!(concat!(env!("OUT_DIR"), "/artifact_hashes.rs"));
}

pub(crate) const DEPLOYMENT: &str =
    include_str!("../../../../../deployments/testnet/deployments.json");

use client::WebClient;
use config::Config;
use events::{bootnode_check, events_listener};
use types::ContractConfig;
use wasm_bindgen::{JsError, prelude::*};
use wasm_bindgen_futures::spawn_local;

#[wasm_bindgen]
pub struct MainThreadHandle {
    client: WebClient,
}

#[wasm_bindgen]
impl MainThreadHandle {
    #[wasm_bindgen(getter, js_name = webClient)]
    pub fn client(&self) -> WebClient {
        self.client.clone()
    }
}

#[wasm_bindgen(js_name = mainThread)]
pub async fn main_thread(config: Config) -> Result<MainThreadHandle, JsError> {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    log::debug!("[MAIN THREAD] starting initialization...");
    let contract_config: &'static ContractConfig =
        Box::leak(Box::new(serde_json::from_str(DEPLOYMENT)?));
    let client = WebClient::new(config.rpc_url(), contract_config)
        .map_err(|e| JsError::new(&e.to_string()))?;
    client
        .ping_storage()
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

    let bootnode_url = bootnode_check(
        config.rpc_url(),
        client.clone(),
        contract_config,
        config.bootnode_url(),
    )
    .await
    .map_err(|e| JsError::new(&e.to_string()))?;

    spawn_local(events_listener(
        config.rpc_url().to_string(),
        bootnode_url,
        client.clone(),
        contract_config,
    ));
    log::debug!("[MAIN THREAD] initialized");
    Ok(MainThreadHandle { client })
}
