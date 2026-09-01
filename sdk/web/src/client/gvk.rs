//! Admin GVK audit cursor for wasm.

use stellar_private_payments::gvk::GvkAudit as NativeGvkAudit;
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

/// Cursor over decrypted pool transacts for admin audit.
///
/// Holds the admin view private key for its lifetime; drop the cursor when
/// finished rather than retaining it longer than needed.
#[wasm_bindgen]
pub struct GvkAudit {
    inner: NativeGvkAudit<StorageBridge>,
}

#[wasm_bindgen]
impl GvkAudit {
    /// Fetch and audit the next transaction, or `null` when exhausted.
    #[wasm_bindgen(js_name = nextTx)]
    pub async fn next_tx(&mut self) -> Result<JsValue, JsError> {
        match self
            .inner
            .next_tx()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?
        {
            None => Ok(JsValue::NULL),
            Some(tx) => Ok(serde_wasm_bindgen::to_value(&tx)?),
        }
    }
}

impl GvkAudit {
    pub(crate) fn new(inner: NativeGvkAudit<StorageBridge>) -> Self {
        Self { inner }
    }
}
