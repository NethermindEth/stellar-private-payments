use stellar_private_payments::types::ContractConfig;
use wasm_bindgen::{JsError, JsValue};

pub(crate) fn parse_contract_config(value: JsValue) -> Result<ContractConfig, JsError> {
    if value.is_null() || value.is_undefined() {
        return Err(JsError::new("contractConfig is required"));
    }
    serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsError::new(&format!("invalid contractConfig: {e}")))
}

pub(crate) fn require_circuits_base_url(value: String) -> Result<String, JsError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(JsError::new("circuitsBaseUrl is required"));
    }
    Ok(format!("{}/", trimmed.trim_end_matches('/')))
}
