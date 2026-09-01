//! Admin GVK audit cursor for wasm.

use std::cell::Cell;

use stellar_private_payments::gvk::GvkAudit as NativeGvkAudit;
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

struct BusyGuard<'a>(&'a Cell<bool>);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

/// Cursor over decrypted pool transacts for admin audit.
///
/// Holds the admin view private key for its lifetime; drop the cursor when
/// finished rather than retaining it longer than needed.
#[wasm_bindgen]
pub struct GvkAudit {
    inner: NativeGvkAudit<StorageBridge>,
    busy: Cell<bool>,
}

#[wasm_bindgen]
impl GvkAudit {
    /// Fetch and audit the next transaction, or `null` when exhausted.
    #[wasm_bindgen(js_name = nextTx)]
    pub async fn next_tx(&mut self) -> Result<JsValue, JsError> {
        if self.busy.replace(true) {
            return Err(JsError::new("GvkAudit.nextTx() already in progress"));
        }
        let _guard = BusyGuard(&self.busy);
        match self.inner.next_tx().await {
            Ok(None) => Ok(JsValue::NULL),
            Ok(Some(tx)) => serde_wasm_bindgen::to_value(&tx).map_err(Into::into),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }
}

impl GvkAudit {
    pub(crate) fn new(inner: NativeGvkAudit<StorageBridge>) -> Self {
        Self {
            inner,
            busy: Cell::new(false),
        }
    }
}
