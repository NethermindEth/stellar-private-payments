use stellar::{Indexer as CoreIndexer, ContractDataStorage, StateFetcher as CoreStateFetcher};
use types::{ContractsEventData, SyncMetadata};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{js_sys, JsFuture};

#[wasm_bindgen(inline_js = "
    import { requestWorker } from './orchestrator.js';
    export { requestWorker };
")]
extern "C" {
    // This tells Rust that this function returns a Promise
    fn requestWorker(msg_type: &str, payload: JsValue) -> js_sys::Promise;
}

struct WasmStorage;

#[async_trait::async_trait(?Send)]
impl ContractDataStorage for WasmStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Option<SyncMetadata>> {
        // Call the JS bridge we built earlier
        let promise = requestWorker("GET_SYNC_STATE", JsValue::NULL);
        let resp = JsFuture::from(promise).await
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let state: Option<SyncMetadata> = serde_wasm_bindgen::from_value(resp).map_err(|e| anyhow::anyhow!("De-serialization failed: {}", e))?;
        Ok(state)
    }

    async fn save_events_batch(&self, data: ContractsEventData) -> anyhow::Result<()> {
        let payload = serde_wasm_bindgen::to_value(&data).map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))?;

        let promise = requestWorker("SAVE_EVENTS", payload);
        JsFuture::from(promise).await
            .map_err(|e| anyhow::anyhow!("Worker failed: {:?}", e))?;
        Ok(())
    }
}

// Runs automatically on module initialization
#[wasm_bindgen(start)]
pub fn init_fetcher() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
}

#[wasm_bindgen]
pub struct Indexer {
    indexer: CoreIndexer<WasmStorage>,
}

#[wasm_bindgen]
impl Indexer {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str) -> Result<Self, JsError> {
        let storage = WasmStorage;
        Ok(Self{
            indexer: CoreIndexer::new(rpc_url, storage).map_err(|e| JsError::new(&e.to_string()))?
        })
    }

    pub async fn fetch_contract_events(&self) -> Result<(), JsError> {
        self.indexer.fetch_contract_events().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(())
    }
}

#[wasm_bindgen]
pub struct StateFetcher {
    fetcher: CoreStateFetcher,
}

#[wasm_bindgen]
impl StateFetcher {

    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: &str) -> Result<Self, JsError> {
        Ok(Self{
            fetcher: CoreStateFetcher::new(rpc_url).map_err(|e| JsError::new(&e.to_string()))?
        })
    }

    pub async fn pool_contract_state(&self) -> Result<JsValue, JsError> {
        let pool_info = self.fetcher.pool_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&pool_info)?)
    }

    pub async fn asp_membership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_membership = self.fetcher.asp_membership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_membership)?)
    }

    pub async fn asp_nonmembership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_nonmembership = self.fetcher.asp_nonmembership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_nonmembership)?)
    }

    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self.fetcher.all_contracts_data().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }
}
