//! Cached [`PrivatePool`] session for browser [`WebClient`] flows.

use super::{WebClient, emit_progress};
use crate::{pool_storage::BridgePoolStorage, prover_bridge::WorkerTransactionProver};
use js_sys::Function;
use std::{cell::RefCell, rc::Rc};
use stellar_private_payments_sdk::{
    PoolError, PrivatePool, PrivatePoolConfig, ProverArtifacts, TransactionProver,
    TransactionSigner,
    types::{AspMembershipSync, ContractConfig},
};
use wasm_bindgen::JsError;

pub(crate) type PoolSessionCell = Rc<RefCell<PoolSession>>;

pub(crate) struct PoolSession {
    pool_contract_id: String,
    user_address: String,
    network_passphrase: String,
    pool: Option<Rc<PrivatePool<BridgePoolStorage>>>,
    signer_progress: Rc<RefCell<Option<Function>>>,
}

impl PoolSession {
    pub(crate) fn new() -> Self {
        Self {
            pool_contract_id: String::new(),
            user_address: String::new(),
            network_passphrase: String::new(),
            pool: None,
            signer_progress: Rc::new(RefCell::new(None)),
        }
    }

    fn clear(&mut self) {
        self.pool_contract_id.clear();
        self.user_address.clear();
        self.network_passphrase.clear();
        self.pool = None;
        *self.signer_progress.borrow_mut() = None;
    }

    fn matches(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        network_passphrase: &str,
    ) -> bool {
        self.pool.is_some()
            && self.pool_contract_id == pool_contract_id
            && self.user_address == user_address
            && self.network_passphrase == network_passphrase
    }
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
    pub fn close_pool(&self) {
        self.pool_session.borrow_mut().clear();
    }

    pub(super) async fn pool_handle(
        &self,
        pool_contract_id: String,
        user_address: String,
        network_passphrase: String,
        on_status: Option<Function>,
    ) -> Result<Rc<PrivatePool<BridgePoolStorage>>, JsError> {
        if self
            .pool_session
            .borrow()
            .matches(&pool_contract_id, &user_address, &network_passphrase)
        {
            let session = self.pool_session.borrow();
            *session.signer_progress.borrow_mut() = on_status;
            return Ok(Rc::clone(
                session.pool.as_ref().expect("matches implies pool is open"),
            ));
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
        let signer_progress = Rc::new(RefCell::new(on_status));
        let signer: Box<dyn TransactionSigner> = Self::wallet_transaction_signer(
            network_passphrase.clone(),
            Rc::clone(&signer_progress),
        );
        let prover: Box<dyn TransactionProver> =
            Box::new(WorkerTransactionProver::new(self.prover_bridge.fork()));
        let pool = Rc::new(
            self.private_pool(config, signer, prover)
                .map_err(pool_err)?,
        );

        {
            let mut session = self.pool_session.borrow_mut();
            session.pool_contract_id = pool_contract_id;
            session.user_address = user_address;
            session.network_passphrase = network_passphrase;
            session.signer_progress = signer_progress;
            session.pool = Some(Rc::clone(&pool));
        }
        Ok(pool)
    }

    pub(super) async fn sync_pool(
        &self,
        pool: &PrivatePool<BridgePoolStorage>,
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
