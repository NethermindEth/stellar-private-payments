//! Browser [`Storage`] — worker-backed local persistence (injectable into
//! [`Client`]).
//!
//! Internal transport uses [`crate::workers::storage::StorageBridge`].

use serde::Deserialize;
use wasm_bindgen::prelude::*;

use crate::{
    protocol::StorageWorkerRequest,
    workers::storage::{StorageBridge, StorageWorker},
};
use gloo_worker::Spawnable;

pub(crate) const DEFAULT_STORAGE_WORKER_URL: &str = "./workers/storage-worker.js";
const DEFAULT_CALL_TIMEOUT_MS: u32 = 5_000;
/// Cold wasm compile + OPFS/SQLite init can exceed the default RPC timeout.
const STORAGE_OPEN_PING_TIMEOUT_MS: u32 = 15_000;

/// Names no address, on purpose: the caller already knows the one it sent, and
/// an address in a rejection is one more place for it to be logged.
const RAW_SURFACE_REFUSAL: &str = "this storage operation is not available over the raw RPC surface: \
     reading or writing an account's privacy keys requires a wallet session opened through \
     Client.account(), which binds the storage worker to that account";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOptions {
    worker_url: Option<String>,
}

/// Worker-backed local persistence. Open once per page, [`fork`] for extra
/// handles.
#[wasm_bindgen]
pub struct Storage {
    bridge: StorageBridge,
}

impl Clone for Storage {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.clone(),
        }
    }
}

impl Storage {
    pub(crate) fn bridge(&self) -> StorageBridge {
        self.bridge.clone()
    }

    pub(crate) async fn open_internal(worker_url: String) -> Result<Self, JsError> {
        crate::wasm_start();

        let storage = Self {
            bridge: StorageBridge::new(
                StorageWorker::spawner()
                    .with_loader(true)
                    .as_module(true)
                    .spawn(&worker_url),
            ),
        };

        storage
            .bridge
            .ping_ms(STORAGE_OPEN_PING_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        Ok(storage)
    }
}

#[wasm_bindgen]
impl Storage {
    /// Spawn the storage worker and verify it is ready.
    ///
    /// Call once per page session. Use [`Storage::fork`] for additional handles
    /// (e.g. app code alongside [`crate::Client`]).
    #[wasm_bindgen(js_name = open)]
    pub async fn open(options: JsValue) -> Result<Storage, JsError> {
        let opts: OpenOptions = if options.is_null() || options.is_undefined() {
            OpenOptions { worker_url: None }
        } else {
            serde_wasm_bindgen::from_value(options)?
        };

        Self::open_internal(
            opts.worker_url
                .unwrap_or_else(|| DEFAULT_STORAGE_WORKER_URL.to_string()),
        )
        .await
    }

    /// New handle to the same storage worker (shared `spp.db`).
    pub fn fork(&self) -> Storage {
        Storage {
            bridge: self.bridge.clone(),
        }
    }

    /// Raw storage-worker RPC. Request/response shapes match the worker
    /// protocol (externally tagged enums, e.g. `{ "DisclaimerState": "G..."
    /// }`).
    ///
    /// # Refused requests
    ///
    /// Requests that read or write an account's private key material are not
    /// available here, and neither is changing which account they serve - see
    /// [`StorageWorkerRequest::requires_bound_session`]. This surface takes
    /// the account as an argument, so anything reachable through it is
    /// addressable by any script on the page that names an address. Key
    /// material is reachable only through [`crate::Client::account`], which
    /// binds the worker to the account whose wallet session it opened.
    ///
    /// The refusal is deliberately not conditional on *which* address is
    /// named: a check of the form "is this the right address?" would still
    /// leave the address a caller-supplied parameter, which is the defect.
    /// Other request kinds are gated by the worker's central
    /// [`StorageWorkerRequest::session_policy`] instead.
    #[wasm_bindgen(js_name = call)]
    pub async fn call(
        &self,
        request: JsValue,
        timeout_ms: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let req: StorageWorkerRequest = serde_wasm_bindgen::from_value(request)?;
        if req.requires_bound_session() {
            return Err(JsError::new(RAW_SURFACE_REFUSAL));
        }
        let timeout = timeout_ms.unwrap_or(DEFAULT_CALL_TIMEOUT_MS);
        let resp = self
            .bridge
            .call(req, timeout)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&resp)?)
    }
}
