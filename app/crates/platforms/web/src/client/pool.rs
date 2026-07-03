//! WASM [`PrivatePool`] session — wraps SDK
//! [`stellar_private_payments_sdk::PrivatePool`].

use std::rc::Rc;

use serde::Deserialize;
use stellar_private_payments_sdk::{
    PrivatePool as SdkPrivatePool, PrivatePoolConfig, Prover, ProverArtifacts, Signer,
    types::ContractConfig,
};
use wasm_bindgen::prelude::*;

use crate::workers::storage::StorageBridge;

use super::WebClient;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoolCreateConfig {
    pub pool_contract: String,
    pub network_passphrase: String,
    pub user_address: String,
}

/// Per-pool session for deposits, transfers, and withdrawals.
#[wasm_bindgen]
pub struct PrivatePool {
    inner: Rc<SdkPrivatePool<StorageBridge>>,
}

impl PrivatePool {
    pub(crate) fn new(inner: Rc<SdkPrivatePool<StorageBridge>>) -> Self {
        Self { inner }
    }

    pub(crate) fn inner(&self) -> &SdkPrivatePool<StorageBridge> {
        &self.inner
    }
}

#[wasm_bindgen]
impl PrivatePool {
    /// Warm prover worker (idempotent). `createPool` already pings once.
    pub async fn initialize(&self) -> Result<(), JsError> {
        Ok(())
    }

    #[wasm_bindgen(js_name = close)]
    pub fn close(self) {}
}

impl WebClient {
    pub(crate) fn wallet_signer(
        network_passphrase: String,
        user_address: String,
    ) -> Box<dyn Signer> {
        Box::new(crate::signer::WalletSigner::new(
            network_passphrase,
            user_address,
        ))
    }

    fn build_pool_config(
        &self,
        contract_config: ContractConfig,
        pool_contract_id: String,
        user_address: String,
    ) -> PrivatePoolConfig {
        PrivatePoolConfig {
            rpc_url: self.rpc_url.clone(),
            contract_config,
            pool_contract_id,
            user_address,
            storage_path: String::new(),
            prover_artifacts: ProverArtifacts::empty(),
        }
    }
}

#[wasm_bindgen]
impl WebClient {
    #[wasm_bindgen(js_name = createPool)]
    pub async fn create_pool(&self, config: JsValue) -> Result<PrivatePool, JsError> {
        let cfg: PoolCreateConfig = serde_wasm_bindgen::from_value(config)?;

        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let contract_config = self.fetcher.contract_config().clone();
        let pool_config =
            self.build_pool_config(contract_config, cfg.pool_contract, cfg.user_address.clone());
        let signer = Self::wallet_signer(cfg.network_passphrase, cfg.user_address);
        let prover: Box<dyn Prover> = Box::new(self.prover_bridge());
        let inner = Rc::new(
            SdkPrivatePool::init(pool_config, self.storage(), signer, prover)
                .map_err(super::pool_err)?,
        );
        Ok(PrivatePool::new(inner))
    }
}
