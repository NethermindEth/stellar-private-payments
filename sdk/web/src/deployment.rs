use stellar_private_payments_sdk::types::ContractConfig;
use wasm_bindgen::JsError;

pub(crate) fn deployment_config() -> Result<&'static ContractConfig, JsError> {
    static CONFIG: std::sync::OnceLock<Result<&'static ContractConfig, String>> =
        std::sync::OnceLock::new();

    let result = CONFIG.get_or_init(|| {
        let config: ContractConfig = serde_json::from_str(crate::DEPLOYMENT)
            .map_err(|e| format!("invalid deployment config: {e}"))?;
        Ok(Box::leak(Box::new(config)))
    });

    match result {
        Ok(config) => Ok(*config),
        Err(message) => Err(JsError::new(message)),
    }
}
