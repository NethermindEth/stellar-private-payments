//! Account-level wasm exports (not scoped to a single pool session).

use serde::Deserialize;
use stellar_private_payments_sdk::chain::StateFetcher;
use wasm_bindgen::prelude::*;

use crate::{client::Client, deployment::deployment_config, signer::WalletSigner};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageWorkerConfig {
    rpc_url: String,
    storage_worker_url: Option<String>,
    prover_worker_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LookupConfig {
    #[serde(flatten)]
    workers: StorageWorkerConfig,
    address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitializeConfig {
    #[serde(flatten)]
    workers: StorageWorkerConfig,
    network_passphrase: String,
    user_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeysConfig {
    #[serde(flatten)]
    workers: StorageWorkerConfig,
    network_passphrase: String,
    user_address: String,
    note_public_key_hex: String,
    encryption_public_key_hex: String,
}

/// Bundled deployment config (contract addresses, pools, network).
#[wasm_bindgen(js_name = contractConfig)]
pub fn contract_config() -> Result<JsValue, JsError> {
    Ok(serde_wasm_bindgen::to_value(deployment_config()?)?)
}

/// On-chain state for all enabled pools plus shared ASP contracts.
#[wasm_bindgen(js_name = allContractsData)]
pub async fn all_contracts_data(rpc_url: String) -> Result<JsValue, JsError> {
    crate::wasm_start();
    let fetcher = StateFetcher::new(&rpc_url, deployment_config()?.clone())
        .map_err(|e| JsError::new(&e.to_string()))?;
    let data = fetcher
        .all_contracts_data()
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_wasm_bindgen::to_value(&data)?)
}

/// Look up a recipient's registered note and encryption public keys.
#[wasm_bindgen(js_name = lookupRegisteredPublicKey)]
pub async fn lookup_registered_public_key(config: JsValue) -> Result<JsValue, JsError> {
    let cfg: LookupConfig = serde_wasm_bindgen::from_value(config)?;
    let client = client_from_workers(&cfg.workers).await?;
    client.lookup_registered_public_key(cfg.address).await
}

/// Derive privacy keys from a wallet signature and persist them locally.
#[wasm_bindgen(js_name = initialize)]
pub async fn initialize(config: JsValue, signer: JsValue) -> Result<(), JsError> {
    let cfg: InitializeConfig = serde_wasm_bindgen::from_value(config)?;
    let wallet_signer =
        WalletSigner::new(signer, cfg.network_passphrase, cfg.user_address.clone())?;
    let client = client_from_workers(&cfg.workers).await?;
    let message = client.key_derivation_message();
    let sig_hex = wallet_signer.sign_wallet_message(&message).await?;
    let signature = crate::signer::hex_signature_to_bytes(&sig_hex)?;
    client
        .derive_save_user_keys(cfg.user_address, signature)
        .await
}

/// Register note and encryption public keys on the deployment-wide registry.
#[wasm_bindgen(js_name = registerPublicKeys)]
pub async fn register_public_keys(config: JsValue, signer: JsValue) -> Result<String, JsError> {
    let cfg: RegisterPublicKeysConfig = serde_wasm_bindgen::from_value(config)?;
    let wallet_signer =
        WalletSigner::new(signer, cfg.network_passphrase, cfg.user_address.clone())?;
    let client = client_from_workers(&cfg.workers).await?;
    client
        .register_public_keys(
            &wallet_signer,
            cfg.user_address,
            cfg.note_public_key_hex,
            cfg.encryption_public_key_hex,
        )
        .await
}

fn default_storage_worker_url() -> String {
    "./workers/storage-worker.js".to_string()
}

fn default_prover_worker_url() -> String {
    "./workers/prover-worker.js".to_string()
}

async fn client_from_workers(workers: &StorageWorkerConfig) -> Result<Client, JsError> {
    Client::connect(
        workers.rpc_url.clone(),
        workers
            .storage_worker_url
            .clone()
            .unwrap_or_else(default_storage_worker_url),
        workers
            .prover_worker_url
            .clone()
            .unwrap_or_else(default_prover_worker_url),
    )
    .await
}
