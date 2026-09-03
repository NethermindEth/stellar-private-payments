use crate::models::contract_config_from_js;
use stellar_private_payments::types::ContractConfig as NativeContractConfig;
use wasm_bindgen::{JsError, JsValue};

pub(crate) fn parse_contract_config(value: JsValue) -> Result<NativeContractConfig, JsError> {
    Ok(contract_config_from_js(value)?.native().clone())
}

pub(crate) fn require_circuits_base_url(value: String) -> Result<String, JsError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(JsError::new("circuitsBaseUrl is required"));
    }
    Ok(format!("{}/", trimmed.trim_end_matches('/')))
}
