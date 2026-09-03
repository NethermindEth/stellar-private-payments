use stellar_private_payments::types::Estimate as NativeEstimate;
use wasm_bindgen::prelude::*;

/// Estimate returned by [`crate::PrivatePool::estimate`].
#[wasm_bindgen]
pub struct PoolEstimate {
    inner: NativeEstimate,
}

#[wasm_bindgen]
impl PoolEstimate {
    #[wasm_bindgen(getter, js_name = txCount)]
    pub fn tx_count(&self) -> u32 {
        self.inner.tx_count
    }
}

impl From<NativeEstimate> for PoolEstimate {
    fn from(inner: NativeEstimate) -> Self {
        Self { inner }
    }
}
