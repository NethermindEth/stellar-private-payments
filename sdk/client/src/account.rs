use types::ContractConfig;

use crate::{Handle, PoolError, PrivatePool, PrivatePoolConfig, Prover, Signer, Storage, SyncMode};

/// Stellar account session (address + signer).
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: String,
    signer: Handle<dyn Signer>,
    sync_mode: SyncMode,
    contract_config: ContractConfig,
    rpc_url: String,
}

impl<S: Storage> Account<S> {
    pub(crate) fn new(
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: String,
        signer: Handle<dyn Signer>,
        sync_mode: SyncMode,
        contract_config: ContractConfig,
        rpc_url: String,
    ) -> Self {
        Self {
            storage,
            prover,
            user_address,
            signer,
            sync_mode,
            contract_config,
            rpc_url,
        }
    }

    pub fn user_address(&self) -> &str {
        &self.user_address
    }

    pub fn signer(&self) -> &Handle<dyn Signer> {
        &self.signer
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Create an owned pool session for `pool_contract_id`.
    pub fn pool(&self, pool_contract_id: impl Into<String>) -> Result<PrivatePool<S>, PoolError> {
        let cfg = PrivatePoolConfig {
            rpc_url: self.rpc_url.clone(),
            contract_config: self.contract_config.clone(),
            pool_contract_id: pool_contract_id.into(),
            user_address: self.user_address.clone(),
        };

        PrivatePool::init(
            cfg,
            self.storage.fork()?,
            self.signer.clone(),
            self.prover.clone(),
            self.sync_mode,
        )
    }
}
