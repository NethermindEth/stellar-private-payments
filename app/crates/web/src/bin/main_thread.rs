use gloo_worker::{WorkerBridge, Spawnable};
use web::sync_worker::{WorkerRequest, WorkerResponse};
use web::chain::{Indexer};
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use stellar::Indexer;
use gloo_timers::future::TimeoutFuture;
use wasm_bindgen_futures::spawn_local;
use std::rc::Rc;
use std::cell::RefCell;
use wasm_bindgen::JsError;

fn main()  -> Result<(), JsError> {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());

    // TODO make compile time feature gate for testnet/mainnet

    spawn_local(async {
        if let Err(e) = init(bridge).await {
            log::error!("[MAIN THREAD] init failed: {e:?}");
        }
    });
}



struct StorageBridge {
    bridge: OneshotBridge<Worker>,
}

impl StorageBridge {
    fn new() -> Self {
        Self {
            bridge: StorageWorker::spawner().spawn("./worker.js"),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for StorageBridge {
    async fn get_sync_state(&self) -> anyhow::Result<Option<SyncMetadata>> {
        match self.bridge.run(WorkerRequest::SyncState).await {
            WorkerResponse::SyncState(state) => Ok(state),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }

    async fn save_events_batch(&self, data: types::ContractsEventData) -> anyhow::Result<()> {
        match self.bridge.run(WorkerRequest::SaveEvents(data)).await {
            WorkerResponse::Saved => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }
}

async fn init(bridge: WorkerBridge<Worker>) -> Result<(), JsError> {
    let storage = StorageBridge::new();
    // TODO make it dependent on the network during the compilation
    let indexer = Indexer::new(
            "https://soroban-testnet.stellar.org",
            storage,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;
    log::debug!("[MAIN THREAD] initialized");
    start_indexer_loop(indexer, 5_000);
    Ok(())
}

fn start_indexer_loop(indexer: Indexer<StorageBridge>, interval_ms: u32) {
    let indexer = Rc::new(indexer);
    let running = Rc::new(RefCell::new(true));

    let indexer_cloned = Rc::clone(&indexer);
    let running_cloned = Rc::clone(&running);

    spawn_local(async move {
        while *running_cloned.borrow() {
            if let Err(e) = indexer_cloned.fetch_contract_events().await {
                log::error!("[MAIN THREAD] fetch_contract_events failed: {e}");
            }

            TimeoutFuture::new(interval_ms).await;
        }
    });
}
