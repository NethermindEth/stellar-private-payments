//! Admin GVK audit cursor for wasm.

use std::cell::RefCell;

use stellar_private_payments::gvk::GvkAudit as NativeGvkAudit;
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

/// Cursor over decrypted pool transacts for admin audit.
///
/// Holds the admin view private key for its lifetime; drop the cursor when
/// finished rather than retaining it longer than needed.
#[wasm_bindgen]
pub struct GvkAudit {
    inner: RefCell<NativeGvkAudit<StorageBridge>>,
}

#[wasm_bindgen]
impl GvkAudit {
    /// Fetch and audit the next transaction, or `null` when exhausted.
    #[wasm_bindgen(js_name = nextTx)]
    // Holding the borrow across `.await` is intentional: it serializes
    // concurrent `nextTx()` calls, turning a reentrant call into a clean
    // error instead of racing the cursor. Safe on wasm's single thread.
    #[allow(clippy::await_holding_refcell_ref)]
    pub async fn next_tx(&self) -> Result<JsValue, JsError> {
        let mut inner = self
            .inner
            .try_borrow_mut()
            .map_err(|_| JsError::new("GvkAudit.nextTx() already in progress"))?;
        match inner.next_tx().await {
            Ok(None) => Ok(JsValue::NULL),
            Ok(Some(tx)) => serde_wasm_bindgen::to_value(&tx).map_err(Into::into),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }
}

impl GvkAudit {
    pub(crate) fn new(inner: NativeGvkAudit<StorageBridge>) -> Self {
        Self {
            inner: RefCell::new(inner),
        }
    }
}
