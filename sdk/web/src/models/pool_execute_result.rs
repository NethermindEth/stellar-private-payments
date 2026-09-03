use stellar_private_payments::{Error, PlanExecutionError, types::TransactionResult};
use wasm_bindgen::prelude::*;

/// Result of pool transact flows (`deposit`, `transfer`, `withdraw`, …).
#[wasm_bindgen]
pub struct PoolExecuteResult {
    status: String,
    hashes: Vec<String>,
    message: Option<String>,
    code: Option<i32>,
}

#[wasm_bindgen]
impl PoolExecuteResult {
    /// `"ok"`, `"failed"`, or `"aspNotReady"`.
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn hashes(&self) -> Vec<String> {
        self.hashes.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn message(&self) -> Option<String> {
        self.message.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<i32> {
        self.code
    }

    /// Plain JSON object with `message`/`code` omitted when absent.
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<JsValue, JsError> {
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("status"),
            &JsValue::from_str(&self.status),
        )
        .map_err(|_| JsError::new("failed to serialize PoolExecuteResult"))?;
        let hashes: js_sys::Array = self.hashes.iter().map(|h| JsValue::from_str(h)).collect();
        js_sys::Reflect::set(&obj, &JsValue::from_str("hashes"), &hashes)
            .map_err(|_| JsError::new("failed to serialize PoolExecuteResult"))?;
        if let Some(message) = &self.message {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("message"),
                &JsValue::from_str(message),
            )
            .map_err(|_| JsError::new("failed to serialize PoolExecuteResult"))?;
        }
        if let Some(code) = self.code {
            js_sys::Reflect::set(
                &obj,
                &JsValue::from_str("code"),
                &JsValue::from_f64(f64::from(code)),
            )
            .map_err(|_| JsError::new("failed to serialize PoolExecuteResult"))?;
        }
        Ok(obj.into())
    }
}

pub(crate) enum ExecuteOutcome {
    Complete(Vec<String>),
    Failed(Error),
    AspNotReady,
}

impl PoolExecuteResult {
    pub(crate) fn from_outcome(outcome: ExecuteOutcome) -> Self {
        match outcome {
            ExecuteOutcome::Complete(hashes) => Self {
                status: "ok".to_string(),
                hashes,
                message: None,
                code: None,
            },
            ExecuteOutcome::Failed(error) => {
                let hashes = match &error {
                    Error::PlanExecution(plan) => {
                        plan.completed.iter().map(|tx| tx.tx_hash.clone()).collect()
                    }
                    _ => Vec::new(),
                };
                let code = wallet_rejection_code(&error);
                let message = error_message(error);
                Self {
                    status: "failed".to_string(),
                    hashes,
                    message: Some(message),
                    code,
                }
            }
            ExecuteOutcome::AspNotReady => Self {
                status: "aspNotReady".to_string(),
                hashes: Vec::new(),
                message: None,
                code: None,
            },
        }
    }
}

impl ExecuteOutcome {
    pub(crate) fn plan(completed: Vec<TransactionResult>, error: Error) -> Self {
        Self::Failed(PlanExecutionError::into_error(completed, error))
    }
}

fn error_message(error: Error) -> String {
    match error {
        Error::PlanExecution(plan) => plan.cause().to_string(),
        other => other.to_string(),
    }
}

fn wallet_rejection_code(error: &Error) -> Option<i32> {
    let cause = match error {
        Error::PlanExecution(plan) => plan.cause(),
        other => other,
    };
    match cause {
        Error::UserRejected(_) => Some(-4),
        _ => None,
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use stellar_private_payments::Error;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn wallet_rejection_maps_to_sep0043_code() {
        let result = PoolExecuteResult::from_outcome(ExecuteOutcome::Failed(Error::UserRejected(
            "stub halt".to_string(),
        )));
        assert_eq!(result.status(), "failed");
        assert_eq!(result.code(), Some(-4));
    }
}
