//! [`PrivatePool`] session reuse for browser [`WebClient`] flows.

use super::{WebClient, emit_progress};
use crate::prover_bridge::WorkerTransactionProver;
use futures::lock::Mutex;
use js_sys::Function;
use std::rc::Rc;
use stellar_private_payments_sdk::{
    PoolError, PrivatePool, PrivatePoolConfig, ProverArtifacts, TransactionProver,
    TransactionSigner,
    types::{AspMembershipSync, ContractConfig},
};
use wasm_bindgen::JsError;

pub(crate) type BridgePool = PrivatePool<crate::pool_storage::BridgePoolStorage>;
pub(crate) type SharedPoolSession = Rc<Mutex<Option<PoolSession>>>;

pub(crate) struct PoolSessionKey {
    pool_contract_id: String,
    user_address: String,
    network_passphrase: String,
}

impl PoolSessionKey {
    fn matches(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        network_passphrase: &str,
    ) -> bool {
        self.pool_contract_id == pool_contract_id
            && self.user_address == user_address
            && self.network_passphrase == network_passphrase
    }
}

pub(crate) struct PoolSession {
    key: PoolSessionKey,
    pub(crate) pool: BridgePool,
}

pub(crate) fn pool_err(error: PoolError) -> JsError {
    match &error {
        PoolError::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        PoolError::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        _ => JsError::new(&error.to_string()),
    }
}

impl WebClient {
    /// Drop the cached pool (e.g. wallet disconnect or account switch).
    pub async fn close_pool(&self) {
        *self.pool.lock().await = None;
    }

    pub(super) async fn ensure_pool(
        &self,
        pool_contract_id: String,
        user_address: String,
        network_passphrase: String,
        on_status: Option<Function>,
    ) -> Result<(), JsError> {
        let reuse_existing = {
            let guard = self.pool.lock().await;
            guard.as_ref().is_some_and(|session| {
                session
                    .key
                    .matches(&pool_contract_id, &user_address, &network_passphrase)
            })
        };

        if reuse_existing {
            let mut guard = self.pool.lock().await;
            let session = guard
                .as_mut()
                .expect("session exists after reuse_existing check");
            session.pool.set_signer(Self::wallet_transaction_signer(
                network_passphrase,
                on_status,
            ));
            return Ok(());
        }

        emit_progress(
            &on_status,
            "pool",
            "load_prover",
            "Starting prover worker…",
            None,
            None,
        );
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let contract_config: ContractConfig = self.fetcher.contract_config().clone();
        let config = PrivatePoolConfig {
            rpc_url: self.rpc_url.clone(),
            contract_config,
            pool_contract_id: pool_contract_id.clone(),
            user_address: user_address.clone(),
            storage_path: String::new(),
            prover_artifacts: ProverArtifacts::empty(),
        };
        let signer: Box<dyn TransactionSigner> =
            Self::wallet_transaction_signer(network_passphrase.clone(), on_status);
        let prover: Box<dyn TransactionProver> =
            Box::new(WorkerTransactionProver::new(self.prover_bridge.fork()));
        let pool = self
            .private_pool(config, signer, Some(prover))
            .map_err(pool_err)?;

        *self.pool.lock().await = Some(PoolSession {
            key: PoolSessionKey {
                pool_contract_id,
                user_address,
                network_passphrase,
            },
            pool,
        });
        Ok(())
    }

    pub(super) async fn sync_pool(
        &self,
        pool: &mut BridgePool,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<(), JsError> {
        emit_progress(
            on_status,
            flow,
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );
        pool.sync().await.map_err(pool_err).map(|_| ())
    }
}
