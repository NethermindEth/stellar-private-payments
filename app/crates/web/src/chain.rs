use stellar::{StateFetcher as CoreStateFetcher};
use types::{ContractsEventData, SyncMetadata};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{js_sys, JsFuture};
use std::cell::RefCell;
use std::rc::Rc;
use wasm_bindgen::prelude::*;

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
