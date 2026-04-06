use stellar::{StateFetcher as CoreStateFetcher};
use wasm_bindgen::prelude::*;
use std::rc::Rc;


#[wasm_bindgen]
#[derive(Clone)]
pub struct StateFetcher {
    fetcher: Rc<CoreStateFetcher>,
}

impl StateFetcher {
    pub fn new(rpc_url: &str) -> Result<Self, JsError> {
        Ok(Self{
            fetcher: Rc::new(CoreStateFetcher::new(rpc_url).map_err(|e| JsError::new(&e.to_string()))?)
        })
    }
}

#[wasm_bindgen]
impl StateFetcher {

    #[wasm_bindgen(js_name = poolContractState)]
    pub async fn pool_contract_state(&self) -> Result<JsValue, JsError> {
        let pool_info = self.fetcher.pool_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&pool_info)?)
    }

    #[wasm_bindgen(js_name = aspMembershipContractState)]
    pub async fn asp_membership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_membership = self.fetcher.asp_membership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_membership)?)
    }

    #[wasm_bindgen(js_name = aspNonmembershipContractState)]
    pub async fn asp_nonmembership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_nonmembership = self.fetcher.asp_nonmembership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_nonmembership)?)
    }

    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self.fetcher.all_contracts_data().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }
}
