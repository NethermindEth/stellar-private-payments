//! Async per-pool private payments API.

use tx_planner::{SpendableNote, Transact};
use types::NoteAmount;

use stellar::{
    Client, Indexer, Limits, ReadXdr, StateFetcher, TransactionEnvelope, TxConfirmStatus,
    confirm_tx, submit_tx,
};

use crate::{
    PoolCore, PreparedTransaction,
    confirm_poll::sleep_between_confirm_polls,
    core::{pool_transact_input, transact_step_for_plan},
    error::PoolError,
    plan::PreparedTransactionPlan,
    prover::Prover,
    signer::Signer,
    storage::Storage,
    transact::transact_request_from_step,
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactChainContext,
        TransactionResult, TransferRecipient,
    },
};

/// Main entry point for a single privacy pool.
pub struct PrivatePool<S> {
    core: PoolCore,
    config: PrivatePoolConfig,
    client: Client,
    fetcher: StateFetcher,
    storage: S,
    prover: Box<dyn Prover>,
    signer: Box<dyn Signer>,
}

impl<S> PrivatePool<S> {
    pub fn init(
        config: PrivatePoolConfig,
        storage: S,
        signer: Box<dyn Signer>,
        prover: Box<dyn Prover>,
    ) -> Result<Self, PoolError> {
        let client = Client::new(&config.rpc_url)
            .map_err(|e| PoolError::Other(format!("rpc client: {e:#}")))?;
        let fetcher = StateFetcher::with_client(client.clone(), config.contract_config.clone())
            .map_err(|e| PoolError::Other(format!("state fetcher: {e:#}")))?;
        Ok(Self {
            core: PoolCore::new(config.chain_config())?,
            config,
            client,
            fetcher,
            storage,
            prover,
            signer,
        })
    }

    pub fn core(&self) -> &PoolCore {
        &self.core
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

    pub fn storage_backend(&self) -> &S {
        &self.storage
    }
}

impl<S: Storage> PrivatePool<S> {
    async fn next_prepared_transaction(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        if plan.is_complete() {
            return Err(PoolError::Other("transaction plan is complete".into()));
        }

        let chain = self.fetch_transact_chain_context().await?;
        let step = if let Some(amount) = plan.deposit_amount() {
            self.deposit_transact_step(amount).await?
        } else if let Some(step) = plan.raw_transact_step() {
            step.clone()
        } else {
            transact_step_for_plan(plan)?
        };
        let req = transact_request_from_step(
            &step,
            &self.config.user_address,
            &self.config.pool_contract_id,
            &chain,
        );

        let params = self.storage.build_transact_params(&req).await?;
        let prepared = self.prover.prove_transact(params).await?;

        plan.finish_proved_tx(&prepared.prepared.output_commitments)?;
        Ok(prepared)
    }

    pub async fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        let chain_config = self.core.config();
        prepared.soroban_tx = self
            .fetcher
            .prepare_pool_transact(
                &chain_config.pool_contract_id,
                &pool_transact_input(prepared),
                &chain_config.user_address,
            )
            .await
            .map_err(|e| PoolError::Other(format!("simulate transaction: {e:#}")))?;

        Ok(())
    }

    pub async fn confirm(&self, hash: &str) -> Result<TransactionResult, PoolError> {
        const CONFIRM_POLL_ATTEMPTS: u32 = 30;

        let rpc = &self.client;

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                sleep_between_confirm_polls().await;
            }
            match confirm_tx(hash, rpc)
                .await
                .map_err(|e| PoolError::Other(format!("confirm transaction: {e:#}")))?
            {
                TxConfirmStatus::Success => {
                    return Ok(TransactionResult {
                        tx_hash: hash.to_string(),
                    });
                }
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

    pub async fn submit(&self, signed_tx: SignedTransaction) -> Result<String, PoolError> {
        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| PoolError::Other(format!("invalid signed transaction xdr: {e}")))?;

        submit_tx(&envelope, &self.client)
            .await
            .map_err(|e| PoolError::Other(format!("submit transaction: {e:#}")))
    }

    pub async fn wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        self.storage
            .spendable_wallet(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    /// Sum of unspent note amounts for this pool and user.
    pub async fn balance(&self) -> Result<NoteAmount, PoolError> {
        let wallet = self.wallet().await?;
        wallet
            .iter()
            .map(|note| note.amount)
            .try_fold(NoteAmount::ZERO, |sum, amount| {
                sum.checked_add(amount)
                    .ok_or_else(|| PoolError::Other("wallet balance overflow".into()))
            })
    }

    pub async fn sync(&self) -> Result<SyncResult, PoolError> {
        let (from_ledger, _) = sync_ledger_bounds(&self.storage).await?;

        let indexer = Indexer::new(
            self.client.clone(),
            self.storage.fork()?,
            &self.config.contract_config,
        )
        .map_err(|e| PoolError::Other(format!("indexer: {e:#}")))?;
        indexer
            .sync_until_caught_up()
            .await
            .map_err(|e| PoolError::Other(format!("indexer sync: {e:#}")))?;

        self.storage.finalize_sync(&self.client).await?;

        let (_, to_ledger) = sync_ledger_bounds(&self.storage).await?;
        Ok(SyncResult {
            from_ledger,
            to_ledger,
            new_commitments: 0,
            new_nullifiers: 0,
            new_membership_leaves: 0,
        })
    }

    pub async fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        let mut plan = self.core.prepare_deposit(amount)?;
        let mut results = self.execute(&mut plan).await?;
        results
            .pop()
            .ok_or_else(|| PoolError::Other("deposit produced no transaction".into()))
    }

    pub async fn transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.core.prepare_transfer(wallet, recipient, amount)?;
        self.execute(&mut plan).await
    }

    pub async fn withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.core.prepare_withdraw(wallet, amount, recipient)?;
        self.execute(&mut plan).await
    }

    /// Execute a single low-level `transact` step (custom inputs/outputs).
    pub async fn transact(&self, step: Transact) -> Result<TransactionResult, PoolError> {
        let mut plan = PreparedTransactionPlan::transact(step);
        let mut results = self.execute(&mut plan).await?;
        results
            .pop()
            .ok_or_else(|| PoolError::Other("transact produced no transaction".into()))
    }

    async fn fetch_transact_chain_context(&self) -> Result<TransactChainContext, PoolError> {
        let (note_pub, _) = self
            .storage
            .user_public_keys(&self.config.user_address)
            .await?;
        self.fetcher
            .transact_chain_context(
                &self.config.pool_contract_id,
                &note_pub,
                &self.config.user_address,
            )
            .await
            .map_err(|e| PoolError::Other(format!("fetch chain context: {e:#}")))
    }

    async fn execute(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut results = Vec::new();
        while !plan.is_complete() {
            let mut prepared = self.next_prepared_transaction(plan).await?;
            self.simulate(&mut prepared).await?;
            let signed = self.signer.sign(&prepared).await?;
            let hash = self.submit(signed).await?;
            let result = self.confirm(&hash).await?;
            results.push(result);
        }
        Ok(results)
    }

    async fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, PoolError> {
        let (note_pub, enc_pub) = self
            .storage
            .user_public_keys(&self.config.user_address)
            .await?;
        self.core.deposit_transact_step(note_pub, enc_pub, amount)
    }
}

async fn sync_ledger_bounds<S: Storage>(storage: &S) -> Result<(u32, u32), PoolError> {
    let metadata = storage
        .get_sync_state()
        .await
        .map_err(|e| PoolError::Other(e.to_string()))?;
    let from = metadata
        .iter()
        .map(|meta| meta.last_indexed_ledger)
        .min()
        .unwrap_or(0);
    let to = metadata
        .iter()
        .map(|meta| meta.last_indexed_ledger)
        .max()
        .unwrap_or(from);
    Ok((from, to))
}
