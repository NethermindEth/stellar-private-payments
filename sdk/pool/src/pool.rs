//! Async per-pool private payments API.

use tx_planner::{SpendableNote, Transact};
use types::NoteAmount;

use stellar::{
    Client, Limits, ReadXdr, StateFetcher, TransactionEnvelope, TxConfirmStatus, confirm_tx,
    submit_tx,
};

use crate::{
    PoolCore, PreparedTransaction,
    confirm_poll::sleep_between_confirm_polls,
    core::{fetch_snapshot_async, pool_transact_input, transact_step_for_plan},
    error::PoolError,
    plan::PreparedTransactionPlan,
    pool_storage::PoolStorage,
    prover::ProverEngine,
    signer::TransactionSigner,
    transact::transact_request_from_step,
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactChainContext,
        TransactionResult, TransferRecipient,
    },
};

#[cfg(target_arch = "wasm32")]
use crate::pool_storage::LocalPoolBackend;

/// Main entry point for a single privacy pool.
pub struct PrivatePool<S> {
    core: PoolCore,
    config: PrivatePoolConfig,
    storage: Option<S>,
    prover: Option<ProverEngine>,
    signer: Box<dyn TransactionSigner>,
}

impl<S> PrivatePool<S> {
    pub fn with_storage(
        config: PrivatePoolConfig,
        storage: S,
        signer: Box<dyn TransactionSigner>,
    ) -> Result<Self, PoolError> {
        Ok(Self {
            core: PoolCore::new(config.chain_config())?,
            config,
            storage: Some(storage),
            prover: None,
            signer,
        })
    }

    pub fn signer(&self) -> &dyn TransactionSigner {
        &*self.signer
    }

    pub fn set_signer(&mut self, signer: Box<dyn TransactionSigner>) {
        self.signer = signer;
    }

    pub fn core(&self) -> &PoolCore {
        &self.core
    }

    pub fn core_mut(&mut self) -> &mut PoolCore {
        &mut self.core
    }

    /// Chain snapshot from the last successful [`Self::sync`] or
    /// [`Self::refresh_chain_context`].
    pub fn chain_context(&self) -> Result<&TransactChainContext, PoolError> {
        self.core.chain_context()
    }

    pub fn set_chain_context(&mut self, chain: TransactChainContext) {
        self.core.set_chain_context(chain);
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, PoolError> {
        self.core.estimate(wallet, amount)
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }

    pub fn pool_storage(&self) -> Result<&S, PoolError> {
        self.storage()
    }

    fn prover(&mut self) -> Result<&mut ProverEngine, PoolError> {
        self.prover.as_mut().ok_or(PoolError::NotInitialized)
    }

    fn ensure_prover(&mut self) -> Result<(), PoolError> {
        if self.prover.is_some() {
            return Ok(());
        }

        let artifacts = &self.config.prover_artifacts;

        self.prover = Some(
            ProverEngine::new(
                &artifacts.proving_key,
                &artifacts.circuit_wasm,
                &artifacts.circuit_r1cs,
            )
            .map_err(|e| PoolError::Other(format!("init prover: {e:#}")))?,
        );

        Ok(())
    }

    fn storage(&self) -> Result<&S, PoolError> {
        self.storage.as_ref().ok_or(PoolError::NotInitialized)
    }
}

impl<S: PoolStorage> PrivatePool<S> {
    pub async fn ensure_storage_ready(&self) -> Result<(), PoolError> {
        self.storage()?.ensure_ready().await
    }

    pub async fn load_prover(&mut self) -> Result<(), PoolError> {
        self.ensure_prover()
    }

    pub async fn next_prepared_transaction(
        &mut self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        self.prove_plan_step(plan).await
    }

    pub async fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        let chain_config = self.core.config();
        let fetcher =
            StateFetcher::new(&chain_config.rpc_url, chain_config.contract_config.clone())
                .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;

        prepared.soroban_tx = fetcher
            .prepare_pool_transact(
                &chain_config.pool_contract_id,
                &pool_transact_input(prepared),
                &chain_config.user_address,
            )
            .await
            .map_err(|e| PoolError::Other(format!("simulate transaction: {e:#}")))?;

        Ok(())
    }

    pub async fn submit(
        &self,
        signed_tx: SignedTransaction,
    ) -> Result<TransactionResult, PoolError> {
        const CONFIRM_POLL_ATTEMPTS: u32 = 30;

        let chain_config = self.core.config();
        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| PoolError::Other(format!("invalid signed transaction xdr: {e}")))?;

        let rpc = Client::new(&chain_config.rpc_url)
            .map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;

        let hash = submit_tx(&envelope, &rpc)
            .await
            .map_err(|e| PoolError::Other(format!("submit transaction: {e:#}")))?;

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                sleep_between_confirm_polls().await;
            }
            match confirm_tx(&hash, &rpc)
                .await
                .map_err(|e| PoolError::Other(format!("confirm transaction: {e:#}")))?
            {
                TxConfirmStatus::Success => return Ok(TransactionResult { tx_hash: hash }),
                TxConfirmStatus::Failed { detail } => {
                    return Err(PoolError::Other(format!("transaction failed{detail}")));
                }
                TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                    return Err(PoolError::Other(format!(
                        "transaction confirmation timed out after 30s (hash: {hash})"
                    )));
                }
                TxConfirmStatus::Pending => {}
            }
        }

        Err(PoolError::Other(format!(
            "transaction confirmation failed (hash: {hash})"
        )))
    }

    pub async fn wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        self.storage()?
            .spendable_wallet(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    pub async fn sync(&mut self) -> Result<SyncResult, PoolError> {
        let (from_ledger, to_ledger) = self
            .storage()?
            .sync_indexer(&self.config.rpc_url, &self.config.contract_config)
            .await?;
        self.refresh_chain_context().await?;
        Ok(SyncResult {
            from_ledger,
            to_ledger,
            new_commitments: 0,
            new_nullifiers: 0,
            new_membership_leaves: 0,
        })
    }

    pub async fn deposit(&mut self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        let mut plan = self.core.prepare_deposit(amount)?;
        let mut results = self.execute(&mut plan).await?;
        results
            .pop()
            .ok_or_else(|| PoolError::Other("deposit produced no transaction".into()))
    }

    pub async fn transfer(
        &mut self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.core.prepare_transfer(wallet, recipient, amount)?;
        self.execute(&mut plan).await
    }

    pub async fn withdraw(
        &mut self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.core.prepare_withdraw(wallet, amount)?;
        self.execute(&mut plan).await
    }

    pub async fn refresh_chain_context(&mut self) -> Result<(), PoolError> {
        let note_pub = self
            .storage()?
            .user_note_pubkey(&self.config.user_address)
            .await?;
        let snapshot = fetch_snapshot_async(self.core.config(), &note_pub).await?;
        self.core.set_chain_context(snapshot);
        Ok(())
    }

    async fn execute(
        &mut self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut results = Vec::new();
        while !plan.is_complete() {
            let mut prepared = self.prove_plan_step(plan).await?;
            self.simulate(&mut prepared).await?;
            let signed = self.signer.sign(&prepared, &self.config).await?;
            let result = self.submit(signed).await?;
            results.push(result);
            self.refresh_chain_context().await?;
        }
        Ok(results)
    }

    async fn prove_plan_step(
        &mut self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        if plan.is_complete() {
            return Err(PoolError::Other("transaction plan is complete".into()));
        }

        let chain = self.core.chain_context()?;
        let step = if let Some(amount) = plan.deposit_amount() {
            self.deposit_transact_step(amount).await?
        } else {
            transact_step_for_plan(plan)?
        };
        let req = transact_request_from_step(
            &step,
            &self.config.user_address,
            &self.config.pool_contract_id,
            chain,
        );

        let params = self.storage()?.build_transact_params(&req).await?;
        self.ensure_prover()?;
        let prepared = self
            .prover()?
            .prove_transact(params)
            .map_err(|e| PoolError::Other(format!("prove: {e:#}")))?;

        plan.finish_proved_tx(&prepared.prepared.output_commitments)?;
        Ok(prepared)
    }

    async fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, PoolError> {
        let (note_pub, enc_pub) = self
            .storage()?
            .user_public_keys(&self.config.user_address)
            .await?;
        self.core.deposit_transact_step(note_pub, enc_pub, amount)
    }
}

#[cfg(target_arch = "wasm32")]
impl PrivatePool<LocalPoolBackend> {
    pub fn new(
        config: PrivatePoolConfig,
        signer: Box<dyn TransactionSigner>,
    ) -> Result<Self, PoolError> {
        Ok(Self {
            core: PoolCore::new(config.chain_config())?,
            config,
            storage: None,
            prover: None,
            signer,
        })
    }

    pub fn initialize(&mut self) -> Result<(), PoolError> {
        self.storage = Some(LocalPoolBackend::open(&self.config.storage_path)?);
        Ok(())
    }
}
