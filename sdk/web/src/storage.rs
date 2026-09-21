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

        #[cfg(feature = "sqlite3mc")]
        storage
            .bridge
            .call(
                StorageWorkerRequest::OpenPlaintext,
                STORAGE_OPEN_PING_TIMEOUT_MS,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

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
    /// Open the explicit migration coordinator, owning both OPFS pools until
    /// close. This handle is for migration commands, not application storage.
    #[cfg(feature = "sqlite3mc")]
    #[wasm_bindgen(js_name = openMigration)]
    pub async fn open_migration(
        worker_url: String,
        key: Vec<u8>,
        create_new: bool,
    ) -> Result<Storage, JsError> {
        let key = crate::protocol::DatabaseKeyTransport(key);
        if key.0.len() != 32 {
            return Err(JsError::new("database key must contain 32 bytes"));
        }
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
            .call(
                StorageWorkerRequest::OpenMigration { key, create_new },
                STORAGE_OPEN_PING_TIMEOUT_MS,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(storage)
    }

    #[cfg(feature = "sqlite3mc")]
    #[wasm_bindgen(js_name = migrationAction)]
    pub async fn migration_action(&self, action: JsValue) -> Result<String, JsError> {
        let action = serde_wasm_bindgen::from_value(action)?;
        match self
            .bridge
            .call_without_timeout(StorageWorkerRequest::Migration(action))
            .await
            .map_err(|e| JsError::new(&e.to_string()))?
        {
            crate::protocol::StorageWorkerResponse::MigrationState(status) => Ok(status),
            _ => Err(JsError::new("unexpected migration response")),
        }
    }

    /// Open the separate encrypted OPFS database. The caller supplies a random
    /// 32-byte key; existing plaintext storage is neither opened nor converted.
    #[cfg(feature = "sqlite3mc")]
    #[wasm_bindgen(js_name = openEncrypted)]
    pub async fn open_encrypted(
        worker_url: String,
        key: Vec<u8>,
        create_new: bool,
    ) -> Result<Storage, JsError> {
        let key = crate::protocol::DatabaseKeyTransport(key);
        if key.0.len() != 32 {
            return Err(JsError::new("database key must contain 32 bytes"));
        }
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
            .call(
                StorageWorkerRequest::OpenEncrypted { key, create_new },
                STORAGE_OPEN_PING_TIMEOUT_MS,
            )
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        storage
            .bridge
            .ping_ms(STORAGE_OPEN_PING_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(storage)
    }

    /// Close the database and release OPFS handles for this storage and all its
    /// forks. Create a new Storage to reopen; this handle cannot be reused.
    pub async fn close(&self) -> Result<(), JsError> {
        self.bridge
            .call(StorageWorkerRequest::Pause, STORAGE_OPEN_PING_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(())
    }

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
    #[wasm_bindgen(js_name = call)]
    pub async fn call(
        &self,
        request: JsValue,
        timeout_ms: Option<u32>,
    ) -> Result<JsValue, JsError> {
        let req: StorageWorkerRequest = serde_wasm_bindgen::from_value(request)?;
        let timeout = timeout_ms.unwrap_or(DEFAULT_CALL_TIMEOUT_MS);
        let resp = self
            .bridge
            .call(req, timeout)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&resp)?)
    }
}
