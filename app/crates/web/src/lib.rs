pub mod worker;
mod contract_state_fetcher;
mod indexer;
mod protocol;
mod config;

use indexer::StorageBridge;
use contract_state_fetcher::StateFetcher;
use config::Config;
use stellar::Indexer;
use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;
use std::rc::Rc;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn main_thread(config: Config) -> Result<StateFetcher, JsError> {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    let storage = StorageBridge::new();
    // TODO allow a user to specify?
    let indexer = Indexer::new(
            config.rpc_url(),
            storage,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
    start_indexer_loop(indexer, 5_000);
    let fetcher = StateFetcher::new(config.rpc_url())?;
    log::debug!("[MAIN THREAD] initialized");
    Ok(fetcher)
}

fn start_indexer_loop(indexer: Indexer<StorageBridge>, interval_ms: u32) {
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
