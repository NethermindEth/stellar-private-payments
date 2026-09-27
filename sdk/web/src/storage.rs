//! Browser [`Storage`] — worker-backed local persistence (injectable into
//! [`Client`]).
//!
//! Internal transport uses [`crate::workers::storage::StorageBridge`].

use serde::Deserialize;
use wasm_bindgen::{JsCast, prelude::*};

use crate::{
    protocol::{Password, StorageWorkerRequest, StorageWorkerResponse},
    workers::storage::{StorageBridge, StorageWorker},
};
use gloo_worker::Spawnable;

pub(crate) const DEFAULT_STORAGE_WORKER_URL: &str = "./workers/storage-worker.js";
const DEFAULT_CALL_TIMEOUT_MS: u32 = 5_000;
/// Cold wasm compile + OPFS/SQLite init can exceed the default RPC timeout.
const STORAGE_OPEN_TIMEOUT_MS: u32 = 15_000;
/// Deriving the key from a password takes a second or two, and encrypting an
/// earlier unencrypted database copies all of it.
const STORAGE_PASSWORD_TIMEOUT_MS: u32 = 120_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpenOptions {
    worker_url: Option<String>,
}

/// Worker-backed local persistence in an encrypted OPFS database, unlocked
/// with the user's password inside the storage worker.
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
            Ok(StorageWorkerResponse::WrongPassword) => Err(wrong_password()),
            Ok(response) => Ok(response),
            Err(e) => Err(js_sys::Error::new(&e.to_string()).into()),
        }
    }
}

/// A wrong password as a JS `Error` with `code: "wrong-password"`, so callers
/// can ask again rather than report a failure.
fn wrong_password() -> JsValue {
    let error = js_sys::Error::new("wrong password");
    // Setting a property on a fresh Error cannot fail.
    let _ = js_sys::Reflect::set(&error, &"code".into(), &"wrong-password".into());
    error.into()
}

#[wasm_bindgen]
impl Storage {
    /// Spawn the storage worker. The database stays closed until [`create`]
    /// or [`unlock`]; ask [`status`] which one it needs. Connect once per
    /// page; use [`fork`] for additional handles.
    ///
    /// [`create`]: Storage::create
    /// [`unlock`]: Storage::unlock
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
            .status()
            .await
            .map_err(|e| JsError::new(&js_message(&e)))?;
        Ok(storage)
    }

    /// What the database needs: `"new"` or `"unencrypted"` (choose a password
    /// with [`Storage::create`]), `"locked"` ([`Storage::unlock`]) or
    /// `"unlocked"`.
    pub async fn status(&self) -> Result<JsValue, JsValue> {
        match self
            .request(StorageWorkerRequest::Status, STORAGE_OPEN_TIMEOUT_MS)
            .await?
        {
            StorageWorkerResponse::Status(status) => Ok(serde_wasm_bindgen::to_value(&status)?),
            other => Err(unexpected(&other)),
        }
    }

    /// Set the first password: create the database, or encrypt the
    /// unencrypted one of an earlier version. The database is open afterwards.
    pub async fn create(&self, password: String) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::Create(Password(password)),
            STORAGE_PASSWORD_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Open the database. A wrong password rejects with
    /// `code: "wrong-password"` and leaves the storage ready for another try.
    pub async fn unlock(&self, password: String) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::Unlock(Password(password)),
            STORAGE_PASSWORD_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Public signing context for the optional wallet unlock method.
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

    /// Add a wallet-derived secret after authenticating the existing password.
    /// The database key stays inside the worker.
    #[wasm_bindgen(js_name = enrollWallet)]
    pub async fn enroll_wallet(
        &self,
        password: String,
        context: JsValue,
        secret: String,
    ) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::EnrollWallet {
                password: Password(password),
                context: serde_wasm_bindgen::from_value(context)?,
                secret: Password(secret),
            },
            STORAGE_PASSWORD_TIMEOUT_MS,
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
                secret: Password(secret),
            },
            STORAGE_PASSWORD_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Replace the password. Rejects with `code: "wrong-password"` when
    /// `current` is wrong; the database itself is not rewritten.
    #[wasm_bindgen(js_name = changePassword)]
    pub async fn change_password(&self, current: String, next: String) -> Result<(), JsValue> {
        self.request(
            StorageWorkerRequest::ChangePassword {
                current: Password(current),
                new: Password(next),
            },
            STORAGE_PASSWORD_TIMEOUT_MS,
        )
        .await?;
        Ok(())
    }

    /// Delete the local database and its password, for a forgotten password.
    /// Everything in it is synced again from the chain and the wallet
    /// afterwards; [`Storage::create`] sets a new password.
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
