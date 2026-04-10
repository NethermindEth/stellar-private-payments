use crate::worker::Worker;
use stellar::{StateFetcher as CoreStateFetcher};
use gloo_worker::oneshot::OneshotBridge;
use gloo_worker::Spawnable;
use crate::protocol::{WorkerRequest, WorkerResponse, UserKeys, Deposit};
use prover::encryption::{ENCRYPTION_MESSAGE, SPENDING_KEY_MESSAGE};
use prover::flows::N_OUTPUTS;
use types::{SMT_DEPTH, EncryptionKeyPair, EncryptionSignature, NoteAmount, NoteKeyPair, SpendingSignature};
use wasm_bindgen::prelude::*;
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use anyhow::anyhow;
use std::rc::Rc;

#[wasm_bindgen]
pub struct WebClient {
    bridge: OneshotBridge<Worker>,
    fetcher: Rc<CoreStateFetcher>,
}

impl Clone for WebClient {
    fn clone(&self) -> Self {
        Self {
            bridge: self.bridge.fork(),
            fetcher: self.fetcher.clone(),
        }
    }
}

async fn with_timeout<T>(
    ms: u32,
    fut: impl std::future::Future<Output = T>,
) -> anyhow::Result<T> {
    let fut = fut.fuse();
    let timeout = TimeoutFuture::new(ms).fuse();

    futures::pin_mut!(fut, timeout);

    futures::select! {
        value = fut => Ok(value),
        _ = timeout => Err(anyhow!("operation timed out after {} ms", ms)),
    }
}

impl WebClient {
    pub fn new(rpc_url: &str) -> anyhow::Result<Self> {
        Ok(Self {
            bridge: Worker::spawner().spawn("./js/worker.js"),
            fetcher: Rc::new(CoreStateFetcher::new(rpc_url)?),
        })
    }

    pub async fn ping(&self) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(5_000, bridge.run(WorkerRequest::Ping)).await?;
        match resp {
            WorkerResponse::Pong => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }


}

#[wasm_bindgen]
impl WebClient {

    #[wasm_bindgen(js_name = poolContractState)]
    pub async fn pool_contract_state(&self) -> Result<JsValue, JsError> {
        let pool_info = self.fetcher.pool_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&pool_info)?)
    }

    #[wasm_bindgen(js_name = aspMembershipContractState)]
    pub async fn asp_membership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_membership = self.fetcher.asp_membership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_membership)?)
    }

    #[wasm_bindgen(js_name = aspNonmembershipContractState)]
    pub async fn asp_nonmembership_contract_state(&self) -> Result<JsValue, JsError> {
        let asp_nonmembership = self.fetcher.asp_nonmembership_contract_state().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&asp_nonmembership)?)
    }

    #[wasm_bindgen(js_name = allContractsData)]
    pub async fn all_contracts_data(&self) -> Result<JsValue, JsError> {
        let data = self.fetcher.all_contracts_data().await.map_err(|e| JsError::new(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&data)?)
    }

    async fn request(&self, req: WorkerRequest, timeout_ms: u32) -> Result<WorkerResponse, JsError> {
        let mut bridge = self.bridge.fork();

        // Handle transport/timeout errors
        let resp = with_timeout(timeout_ms, bridge.run(req))
            .await
            .map_err(|e| JsError::new(&format!("Worker Communication Error: {}", e)))?;

        match resp {
            WorkerResponse::Error(e) => Err(JsError::new(&e)),
            _ => Ok(resp),
        }
    }

    #[wasm_bindgen(js_name = encryptionDerivationMessage)]
    pub fn encryption_derivation_message(&self) -> String {
        ENCRYPTION_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = spendingKeyMessage)]
    pub fn spending_key_message(&self) -> String {
        SPENDING_KEY_MESSAGE.to_string()
    }

    #[wasm_bindgen(js_name = deriveAndSaveUserKeys)]
    pub async fn derive_save_user_keys(&self, address: String, spending_sig: Vec<u8>, encryption_sig: Vec<u8>) -> Result<(), JsError> {
        let req = WorkerRequest::DeriveSaveUserKeys(
            address,
            SpendingSignature(spending_sig),
            EncryptionSignature(encryption_sig)
        );

        match self.request(req, 5_000).await? {
            WorkerResponse::Saved => Ok(()),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getUserKeys)]
    pub async fn get_user_keys(&self, address: String) -> Result<JsValue, JsError> {
        let req = WorkerRequest::UserKeys(
            address,
        );

        match self.request(req, 1_000).await? {
            WorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = getRecentPublicKeys)]
    pub async fn get_recent_public_keys(&self, limit: u32) -> Result<JsValue, JsError> {
        let req = WorkerRequest::RecentPubKeys(
            limit,
        );

        match self.request(req, 1_000).await? {
            WorkerResponse::UserKeys(keys) => Ok(serde_wasm_bindgen::to_value(&keys)?),
            other => Err(JsError::new(&format!("Unexpected response: {:?}", other))),
        }
    }

    #[wasm_bindgen(js_name = proveDepositPrepareTx)]
    pub async fn prove_deposit_prepare_tx(&self, user_address: String, membership_blinding: Field, amount_stroops: ExtAmount, output_amounts: [NoteAmount; N_OUTPUTS]) -> Result<JsValue, JsError> {
        let data = self.fetcher.all_contracts_data().await.map_err(|e| JsError::new(&e.to_string()))?;
        // for non membership fetches proofs on-demand from the contract rather than syncing locally
        let non_membership_proof = self.fetcher.get_nonmembership_proof().await.map_err(|e| JsError::new(&e.to_string()))?;

        let req = Deposit{
            user_address,
            membership_blinding,
            amount_stroops: NoteAmount::from(amount_stroops),
            pool_root: data.pool.merkle_root,
            pool_address: data.pool.contract_id,
            aspmem_root: data.asp_membership.root,
            aspmem_ledger: data.asp_membership.ledger,
            output_amounts,
            tree_depth: data.pool.merkle_levels,
            smt_depth: SMT_DEPTH,
            non_membership_proof,
        };

        todo!()
    }

    #[wasm_bindgen(js_name = proveWithdrawPrepareTx)]
    pub async fn prove_withdraw_prepare_tx(&self, limit: u32) -> Result<JsValue, JsError> {
        todo!()
    }

    #[wasm_bindgen(js_name = proveTransferPrepareTx)]
    pub async fn prove_transfer_prepare_tx(&self, limit: u32) -> Result<JsValue, JsError> {
        todo!()
    }

    #[wasm_bindgen(js_name = proveTransactPrepareTx)]
    pub async fn prove_transact_prepare_tx(&self, limit: u32) -> Result<JsValue, JsError> {
        todo!()
    }
}

#[async_trait::async_trait(?Send)]
impl stellar::ContractDataStorage for WebClient {
    async fn get_sync_state(&self) -> anyhow::Result<Option<types::SyncMetadata>> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(5_000, bridge.run(WorkerRequest::SyncState)).await?;
        match resp {
            WorkerResponse::SyncState(state) => Ok(state),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }

    async fn save_events_batch(&self, data: types::ContractsEventData) -> anyhow::Result<()> {
        let mut bridge = self.bridge.fork();
        let resp = with_timeout(10_000, bridge.run(WorkerRequest::SaveEvents(data))).await?;
        match resp {
            WorkerResponse::Saved => Ok(()),
            WorkerResponse::Error(e) => Err(anyhow::anyhow!(e)),
            other => Err(anyhow::anyhow!("unexpected response: {:?}", other)),
        }
    }
}
