mod client;
mod config;
#[cfg(target_arch = "wasm32")]
mod merkle_benchmark;
mod protocol;
pub mod workers;

use client::WebClient;
use config::Config;
use gloo_timers::future::TimeoutFuture;
use std::rc::Rc;
use stellar::Indexer;
use wasm_bindgen::{JsError, prelude::*};
use wasm_bindgen_futures::spawn_local;

#[cfg(target_arch = "wasm32")]
pub use merkle_benchmark::benchmark_merkle_prefix_tree;

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
    let client = WebClient::new(config.rpc_url()).map_err(|e| JsError::new(&e.to_string()))?;
    client
        .ping_storage()
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;
    let indexer = Indexer::init(config.rpc_url(), client.clone())
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;
    start_indexer_loop(indexer, 5_000);
    log::debug!("[MAIN THREAD] initialized");
    Ok(MainThreadHandle { client })
}

fn start_indexer_loop(indexer: Indexer<WebClient>, interval_ms: u32) {
    let indexer = Rc::new(indexer);

    let indexer_cloned = Rc::clone(&indexer);
    spawn_local(async move {
        log::debug!("[INDEXER] looping");

        // Fetch events in rounds (internal indexer loop with termination conditions)
        // or at least 5s (ledger time)
        loop {
            if let Err(e) = indexer_cloned.fetch_contract_events().await {
                log::error!("[INDEXER] round failed: {e}");
            }

            TimeoutFuture::new(interval_ms).await;
        }
    });
}
