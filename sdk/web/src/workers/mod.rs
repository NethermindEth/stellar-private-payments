#[cfg(target_arch = "wasm32")]
pub mod prover;
#[cfg(target_arch = "wasm32")]
pub mod storage;

#[cfg(target_arch = "wasm32")]
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Wrapper that carries a correlation/operation ID across the gloo-worker
/// boundary. The worker re-attaches `correlation_id` as a tracing span field.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct CorrelatedRequest<T> {
    pub correlation_id: String,
    pub payload: T,
}

/// Handle [`crate::client::Client::new`] takes.
#[wasm_bindgen]
pub struct ProverHandle(stellar_private_payments::ProverHandle);

impl ProverHandle {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(inner: stellar_private_payments::ProverHandle) -> Self {
        Self(inner)
    }

    pub(crate) fn inner(&self) -> stellar_private_payments::ProverHandle {
        self.0.clone()
    }
}

/// Handle [`crate::client::Client::new`] takes.
#[wasm_bindgen]
pub struct StorageHandle(stellar_private_payments::StorageHandle);

impl StorageHandle {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn new(inner: stellar_private_payments::StorageHandle) -> Self {
        Self(inner)
    }

    pub(crate) fn inner(&self) -> stellar_private_payments::StorageHandle {
        self.0.clone()
    }
}
