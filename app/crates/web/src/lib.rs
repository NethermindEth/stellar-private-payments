pub mod worker;
mod contract_state_fetcher;
mod worker_client;
mod protocol;
mod config;

use worker_client::WorkerClient;
use contract_state_fetcher::StateFetcher;
use config::Config;
use stellar::Indexer;
use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;
use std::rc::Rc;
use wasm_bindgen::JsError;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MainThreadHandle {
    fetcher: StateFetcher,
    worker_client: WorkerClient,
}

#[wasm_bindgen]
impl MainThreadHandle {
    #[wasm_bindgen(getter)]
    pub fn fetcher(&self) -> StateFetcher {
        self.fetcher.clone()
    }

    #[wasm_bindgen(getter, js_name = workerClient)]
    pub fn worker_client(&self) -> WorkerClient {
        self.worker_client.clone()
    }
}

#[wasm_bindgen(js_name = mainThread)]
pub async fn main_thread(config: Config) -> Result<MainThreadHandle, JsError> {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    let fetcher = StateFetcher::new(config.rpc_url())?;
    let worker_client = WorkerClient::new();
    worker_client.ping().await.map_err(|e| JsError::new(&e.to_string()))?;
    let indexer = Indexer::new(
            config.rpc_url(),
            worker_client.clone(),
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
    start_indexer_loop(indexer, 5_000);
    log::debug!("[MAIN THREAD] initialized");
    Ok(MainThreadHandle {
            fetcher,
            worker_client,
        })
}

fn start_indexer_loop(indexer: Indexer<WorkerClient>, interval_ms: u32) {
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
