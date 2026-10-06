#![cfg(target_arch = "wasm32")]

use stellar_private_payments::state::database_key::DatabaseKey;
use stellar_private_payments_web::opfs::open_wallet;
use wasm_bindgen_test::*;

fn key() -> DatabaseKey {
    DatabaseKey::new([42; 32])
}

wasm_bindgen_test_configure!(run_in_dedicated_worker);

fn directory(label: &str) -> String {
    format!(
        "spp-opfs-test-{label}-{}-{}",
        js_sys::Date::now(),
        js_sys::Math::random()
    )
}

#[wasm_bindgen_test]
async fn wallet_persists_keys_settings_disclaimer_and_history() -> anyhow::Result<()> {
    console_error_panic_hook::set_once();
    let directory = directory("persist");
    let mut wallet = open_wallet(&directory, &key(), true).await?;
    wallet
        .set_setting_json("persistent", &serde_json::json!({"value": 42}))
        .await?;
    let disclaimer = wallet.get_disclaimer_state("GTEST").await?;
    wallet
        .accept_current_disclaimer("GTEST", &disclaimer.disclaimer_hash_hex)
        .await?;
    wallet
        .insert_operation(
            "GTEST",
            "CPOOL",
            "deposit",
            "42",
            "in",
            None,
            Some("tx-test"),
        )
        .await?;
    let signature = stellar_private_payments::types::KeyDerivationSignature(vec![42; 64]);
    let (notes, encryption) =
        stellar_private_payments::zk::encryption::derive_encryption_and_note_keypairs(
            signature.clone(),
        )?;
    let blinding =
        stellar_private_payments::zk::encryption::derive_membership_blinding(&signature, "test")?;
    wallet
        .save_encryption_and_note_keypairs("GTEST", &notes, &encryption, &blinding)
        .await?;
    drop(wallet);
    let mut wallet = open_wallet(&directory, &key(), false).await?;
    assert_eq!(
        wallet
            .get_setting_json::<serde_json::Value>("persistent")
            .await?,
        Some(serde_json::json!({"value":42}))
    );
    assert!(wallet.get_disclaimer_state("GTEST").await?.accepted);
    let operations = wallet.list_operations("GTEST", "CPOOL", 10).await?;
    assert_eq!(operations.len(), 1);
    assert!(operations[0].created_at > 1_700_000_000);
    assert!(wallet.get_private_keys("GTEST").await?.is_some());
    Ok(())
}

#[wasm_bindgen_test]
async fn exclusive_lock_is_released_on_close_and_failed_open() -> anyhow::Result<()> {
    let directory = directory("lock");
    let wallet = open_wallet(&directory, &key(), true).await?;
    let error = open_wallet(&directory, &key(), false)
        .await
        .err()
        .expect("second open must be locked");
    assert!(error.to_string().contains("NoModificationAllowedError"));
    drop(wallet);
    let wallet = open_wallet(&directory, &key(), false).await?;
    drop(wallet);
    let failed_directory = format!("{directory}-failure");
    let held_wal = hold_wal(&failed_directory).await.expect("hold WAL");
    assert!(open_wallet(&failed_directory, &key(), true).await.is_err());
    release_wal(&held_wal);
    open_wallet(&failed_directory, &key(), true).await?;
    Ok(())
}

use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/tests/opfs-lifecycle.js")]
extern "C" {
    #[wasm_bindgen(catch, js_name = holdWal)]
    async fn hold_wal(directory: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = releaseWal)]
    fn release_wal(handle: &JsValue);
    #[wasm_bindgen(catch, js_name = runWorker)]
    async fn run_worker(directory: &str, write: bool) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = walBytes)]
    async fn wal_bytes(directory: &str) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, js_name = storedBytes)]
    async fn stored_bytes(directory: &str) -> Result<JsValue, JsValue>;
}

thread_local! {
    static CRASH_WALLET: std::cell::RefCell<Option<stellar_private_payments::state::SqliteStorage>> = const { std::cell::RefCell::new(None) };
}

#[wasm_bindgen(js_name = crashWriter)]
pub async fn crash_writer(directory: String) -> Result<bool, JsError> {
    console_error_panic_hook::set_once();
    let mut wallet = open_wallet(&directory, &key(), true)
        .await
        .map_err(|error| JsError::new(&error.to_string()))?;
    // Leave committed transactions in the WAL, then terminate the worker.
    for value in 0..12 {
        wallet
            .set_setting_json("crash-value", &value)
            .await
            .map_err(|error| JsError::new(&error.to_string()))?;
    }
    CRASH_WALLET.with(|cell| *cell.borrow_mut() = Some(wallet));
    Ok(true)
}

#[wasm_bindgen(js_name = crashReader)]
pub async fn crash_reader(directory: String) -> Result<bool, JsError> {
    console_error_panic_hook::set_once();
    let wallet = open_wallet(&directory, &key(), false)
        .await
        .map_err(|error| JsError::new(&error.to_string()))?;
    Ok(wallet
        .get_setting_json::<u32>("crash-value")
        .await
        .map_err(|error| JsError::new(&error.to_string()))?
        == Some(11))
}

#[wasm_bindgen_test]
async fn committed_wal_survives_worker_termination() -> Result<(), JsValue> {
    let directory = directory("terminate");
    assert_eq!(run_worker(&directory, true).await?.as_bool(), Some(true));
    let wal = js_sys::Uint8Array::new(&wal_bytes(&directory).await?).to_vec();
    assert!(
        wal.len() > 4096,
        "committed encrypted pages must be in the WAL"
    );
    assert!(
        !wal.windows(b"crash-value".len())
            .any(|w| w == b"crash-value")
    );
    assert_eq!(run_worker(&directory, false).await?.as_bool(), Some(true));
    Ok(())
}

#[wasm_bindgen_test]
async fn wrong_key_and_create_policy_preserve_ciphertext() -> Result<(), JsValue> {
    let directory = directory("ciphertext");
    let mut wallet = open_wallet(&directory, &key(), true)
        .await
        .expect("create encrypted wallet");
    wallet
        .set_setting_json("confidential", &"distinct-private-marker-594893")
        .await
        .expect("write confidential setting");
    drop(wallet);
    let before = stored_bytes(&directory).await?;
    let bytes = js_sys::Uint8Array::new(&before).to_vec();
    assert!(
        !bytes
            .windows(b"distinct-private-marker-594893".len())
            .any(|w| w == b"distinct-private-marker-594893")
    );
    assert!(
        open_wallet(&directory, &DatabaseKey::new([43; 32]), false)
            .await
            .is_err()
    );
    assert!(open_wallet(&directory, &key(), true).await.is_err());
    assert_eq!(
        js_sys::Uint8Array::new(&stored_bytes(&directory).await?).to_vec(),
        bytes
    );
    let wallet = open_wallet(&directory, &key(), false)
        .await
        .expect("reopen encrypted wallet");
    assert_eq!(
        wallet
            .get_setting_json::<String>("confidential")
            .await
            .expect("read confidential setting")
            .as_deref(),
        Some("distinct-private-marker-594893")
    );
    drop(wallet);
    Ok(())
}

#[wasm_bindgen(module = "/tests/opfs-lifecycle.js")]
extern "C" {
    #[wasm_bindgen(js_name = storageWorkerUrl)]
    fn storage_worker_url() -> String;
    #[wasm_bindgen(js_name = revokeWorkerUrl)]
    fn revoke_worker_url(url: &str);
}

#[wasm_bindgen(js_name = startStorageWorker)]
pub fn start_storage_worker() {
    stellar_private_payments_web::workers::storage::worker_main();
}

#[wasm_bindgen_test]
async fn production_worker_persists_and_reopens() -> Result<(), JsValue> {
    use stellar_private_payments_web::StorageBridge;
    let url = storage_worker_url();
    assert!(
        StorageBridge::open(js_sys::JSON::parse(
            &serde_json::json!({"workerUrl":url,"createNew":true}).to_string(),
        )?)
        .await
        .is_err(),
        "a key is required even for a new database"
    );
    let options = js_sys::JSON::parse(
        &serde_json::json!({"workerUrl":url,"key":vec![42;32],"createNew":true}).to_string(),
    )
    .expect("options");
    let bridge = StorageBridge::open(options.clone()).await?;
    bridge
        .call_js(
            js_sys::JSON::parse(r#"{"SetSetting":{"key":"new-only","value_json":"456"}}"#)?,
            None,
        )
        .await?;
    let fork = bridge.fork_js();
    bridge.call_js(JsValue::from_str("Pause"), None).await?;
    assert!(
        fork.to_handle().await.is_err(),
        "close must revoke existing forks"
    );
    drop(fork);
    assert!(
        bridge.to_handle().await.is_err(),
        "paused worker must not report ready"
    );
    drop(bridge);

    js_sys::Reflect::set(&options, &JsValue::from_str("createNew"), &JsValue::FALSE)?;
    let bridge = StorageBridge::open(options).await?;
    let value = bridge
        .call_js(js_sys::JSON::parse(r#"{"GetSetting":"new-only"}"#)?, None)
        .await?;
    let value: serde_json::Value = serde_wasm_bindgen::from_value(value).expect("response");
    assert_eq!(value, serde_json::json!({"Setting":"456"}));
    bridge.call_js(JsValue::from_str("Pause"), None).await?;
    drop(bridge);
    revoke_worker_url(&url);
    Ok(())
}
