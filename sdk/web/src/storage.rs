//! Browser [`Storage`] — worker-backed local persistence (injectable into
//! [`Client`]).
//!
//! Internal transport uses [`crate::workers::storage::StorageBridge`].

use serde::Deserialize;
use wasm_bindgen::{JsCast, prelude::*};

use crate::{
    protocol::{StorageWorkerRequest, StorageWorkerResponse, UnlockSecret},
    workers::storage::{StorageBridge, StorageWorker},
};
use gloo_worker::Spawnable;

pub(crate) const DEFAULT_STORAGE_WORKER_URL: &str = "./workers/storage-worker.js";
const DEFAULT_CALL_TIMEOUT_MS: u32 = 5_000;
/// Cold wasm compile + OPFS/SQLite init can exceed the default RPC timeout.
const STORAGE_OPEN_TIMEOUT_MS: u32 = 15_000;
/// Legacy envelope opening and plaintext migration can be expensive.
const STORAGE_UNLOCK_TIMEOUT_MS: u32 = 120_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOptions {
    worker_url: Option<String>,
}

/// Handle [`crate::client::Client::new`] takes.
#[wasm_bindgen]
pub struct StorageHandle(stellar_private_payments::Handle<dyn stellar_private_payments::Storage>);

impl StorageHandle {
    pub(crate) fn inner(
        &self,
    ) -> stellar_private_payments::Handle<dyn stellar_private_payments::Storage> {
        self.0.clone()
    }
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

    async fn request(
        &self,
        request: StorageWorkerRequest,
        timeout_ms: u32,
    ) -> Result<StorageWorkerResponse, JsValue> {
        // Own a bridge for the whole request: JS may drop this handle while
        // the request is pending, and the worker must outlive the request.
        let bridge = self.bridge.clone();
        match bridge.call(request, timeout_ms).await {
            Ok(response) => Ok(response),
            Err(e) => Err(js_sys::Error::new(&e.to_string()).into()),
        }
    }
}

#[wasm_bindgen]
impl Storage {
    /// Spawn the storage worker and open the public chain cache. Private data
    /// stays closed until [`create_wallet`] or [`unlock_wallet`]; ask
    /// [`status`] which it needs. Connect once per page; use [`fork`] for
    /// additional handles.
    ///
    /// [`create_wallet`]: Storage::create_wallet
    /// [`unlock_wallet`]: Storage::unlock_wallet
    /// [`status`]: Storage::status
    /// [`fork`]: Storage::fork
    pub async fn connect(options: JsValue) -> Result<Storage, JsError> {
        let opts: OpenOptions = if options.is_null() || options.is_undefined() {
            OpenOptions { worker_url: None }
        } else {
            serde_wasm_bindgen::from_value(options)?
        };
        crate::wasm_start();
        let storage = Self {
            bridge: StorageBridge::new(
                StorageWorker::spawner()
                    .with_loader(true)
                    .as_module(true)
                    .spawn(
                        &opts
                            .worker_url
                            .unwrap_or_else(|| DEFAULT_STORAGE_WORKER_URL.to_string()),
                    ),
            ),
        };
        // Return only once the worker has loaded and taken the OPFS pool. A
        // handle JS drops while the worker still loads can lose the worker,
        // and a second tab's lock surfaces here rather than on first use.
        storage
            .request(StorageWorkerRequest::OpenPublic, STORAGE_OPEN_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&js_message(&e)))?;
        Ok(storage)
    }

    /// What the database needs: `"new"` or `"unencrypted"` (approve wallet
    /// setup with [`Storage::create_wallet`]), `"locked"`
    /// ([`Storage::unlock_wallet`]) or `"unlocked"`.
    pub async fn status(&self) -> Result<JsValue, JsValue> {
        match self
            .request(StorageWorkerRequest::Status, STORAGE_OPEN_TIMEOUT_MS)
            .await?
        {
            StorageWorkerResponse::Status(status) => Ok(serde_wasm_bindgen::to_value(&status)?),
            other => Err(unexpected(&other)),
        }
    }

    /// Public signing context for the enrolled wallet.
    #[wasm_bindgen(js_name = walletContext)]
    pub async fn wallet_context(&self) -> Result<JsValue, JsValue> {
        match self
            .request(StorageWorkerRequest::WalletContext, STORAGE_OPEN_TIMEOUT_MS)
            .await?
        {
            StorageWorkerResponse::WalletContext(context) => {
                Ok(serde_wasm_bindgen::to_value(&context)?)
            }
            other => Err(unexpected(&other)),
        }
    }

    /// Create a wallet-only private vault. The database key stays in the
    /// worker.
    #[wasm_bindgen(js_name = createWallet)]
    pub async fn create_wallet(&self, context: JsValue, secret: String) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::CreateWallet {
                context: serde_wasm_bindgen::from_value(context)?,
                secret: UnlockSecret(secret),
            },
            STORAGE_UNLOCK_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Unlock using the secret derived from the enrolled wallet signature.
    #[wasm_bindgen(js_name = unlockWallet)]
    pub async fn unlock_wallet(&self, context: JsValue, secret: String) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::UnlockWallet {
                context: serde_wasm_bindgen::from_value(context)?,
                secret: UnlockSecret(secret),
            },
            STORAGE_UNLOCK_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Explicitly delete all local public and private data.
    pub async fn reset(&self) -> Result<(), JsValue> {
        self.request(StorageWorkerRequest::Reset, STORAGE_OPEN_TIMEOUT_MS)
            .await?;
        Ok(())
    }

    /// Close the database and release OPFS handles for this storage and all its
    /// forks. Connect a new Storage to reopen; this handle cannot be reused.
    pub async fn close(&self) -> Result<(), JsError> {
        self.bridge
            .call(StorageWorkerRequest::Pause, STORAGE_OPEN_TIMEOUT_MS)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(())
    }

    /// New handle to the same storage worker and database.
    pub fn fork(&self) -> Storage {
        Storage {
            bridge: self.bridge.clone(),
        }
    }

    /// Forks and pings before converting to a [`StorageHandle`].
    #[wasm_bindgen(js_name = toHandle)]
    pub async fn to_handle(&self) -> Result<StorageHandle, JsError> {
        let bridge = self.fork().bridge;
        bridge
            .ping()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(StorageHandle(stellar_private_payments::Handle::from_box(
            Box::new(bridge) as Box<dyn stellar_private_payments::Storage>,
        )))
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

fn unexpected(response: &StorageWorkerResponse) -> JsValue {
    js_sys::Error::new(&format!("unexpected storage response: {response:?}")).into()
}

fn js_message(error: &JsValue) -> String {
    error
        .dyn_ref::<js_sys::Error>()
        .map(|e| String::from(e.message()))
        .unwrap_or_else(|| format!("{error:?}"))
}
