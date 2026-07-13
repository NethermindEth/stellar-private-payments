use types::ContractConfig;

use crate::{
    Handle, PoolError, PrivatePool, PrivatePoolConfig, Prover, ProverArtifacts, Signer, Storage,
    SyncMode,
};

/// Stellar account session (address + signer).
///
/// Construct via [`crate::Client::account`].
pub struct Account<S: Storage> {
    storage: S,
    prover: Handle<dyn Prover>,
    user_address: String,
    signer: Handle<dyn Signer>,
    sync_mode: SyncMode,
}

impl<S: Storage> Account<S> {
    pub(crate) fn new(
        storage: S,
        prover: Handle<dyn Prover>,
        user_address: String,
        signer: Handle<dyn Signer>,
        sync_mode: SyncMode,
    ) -> Self {
        Self {
            storage,
            prover,
            user_address,
            signer,
            sync_mode,
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

    /// Create an owned pool
    pub fn pool(
        &self,
        rpc_url: impl Into<String>,
        contract_config: ContractConfig,
        pool_contract_id: impl Into<String>,
    ) -> Result<PrivatePool<S>, PoolError> {
        let cfg = PrivatePoolConfig {
            rpc_url: rpc_url.into(),
            contract_config,
            pool_contract_id: pool_contract_id.into(),
            user_address: self.user_address.clone(),
            // not used by the pool runtime when storage+prover are injected,
            // but still part of the existing config type.
            storage_path: String::new(),
            prover_artifacts: ProverArtifacts::empty(),
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
