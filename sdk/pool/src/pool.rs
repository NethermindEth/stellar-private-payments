//! Async per-pool private payments API

use tx_planner::{SpendableNote, Transact};
use types::{EncryptionPublicKey, NoteAmount, NotePublicKey, UserNoteSummary};

use stellar::{
    Client, Indexer, Limits, ReadXdr, StateFetcher, TransactionEnvelope, TxConfirmStatus,
    confirm_tx, submit_tx,
};

use crate::{
    PoolCore, PreparedTransaction,
    core::{pool_transact_input, transact_step_for_plan},
    disclosure::{
        DisclosureInputsRequest, DisclosureProveParams, DisclosureRequest,
        verify_disclosure_receipt,
    },
    error::PoolError,
    plan::PreparedTransactionPlan,
    prover::Prover,
    signer::Signer,
    sleep::sleep,
    storage::Storage,
    transact::transact_request_from_step,
    types::{
        AspMembershipSync, DisclosureContext, DisclosureReceipt, DisclosureVerificationReport,
        Estimate, PrivatePoolConfig, SignedTransaction, TransactChainContext, TransactionResult,
        TransferRecipient,
    },
};

const POLL_INTERVAL_MS: u32 = 1_000;
const SYNC_MAX_RETRIES: u32 = 30;
const DISCLOSE_MAX_RETRIES: u32 = 30;

/// Main entry point for a single privacy pool
pub struct PrivatePool<S> {
    config: PrivatePoolConfig,
    core: PoolCore,
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

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }
}

impl<S: Storage> PrivatePool<S> {
    // high level methods

    pub async fn balance(&self) -> Result<NoteAmount, PoolError> {
        let wallet = self.spendable_notes().await?;
        wallet
            .iter()
            .map(|note| note.amount)
            .try_fold(NoteAmount::ZERO, |sum, amount| {
                sum.checked_add(amount)
                    .ok_or_else(|| PoolError::Other("wallet balance overflow".into()))
            })
    }

    pub async fn notes(&self) -> Result<Vec<UserNoteSummary>, PoolError> {
        self.storage
            .notes(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    pub async fn sync(&self) -> Result<(), PoolError> {
        let indexer = Indexer::init_with_client(
            self.client.clone(),
            self.storage.fork()?,
            &self.config.contract_config,
        )
        .await
        .map_err(|e| PoolError::Other(format!("indexer: {e:#}")))?;
        indexer
            .catch_up()
            .await
            .map_err(|e| PoolError::Other(format!("indexer catch-up: {e:#}")))?;

        self.storage.process_pending_state().await
    }

    pub async fn estimate(&self, amount: NoteAmount) -> Result<Estimate, PoolError> {
        let wallet = self.spendable_notes().await?;
        self.core.estimate(&wallet, amount)
    }

    pub async fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        let mut plan = self.prepare_deposit(amount)?;
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| PoolError::Other("deposit produced no transaction".into()))
    }

    pub async fn transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.prepare_transfer(wallet, recipient, amount)?;
        self.execute(&mut plan).await
    }

    pub async fn withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        let mut plan = self.prepare_withdraw(wallet, amount, recipient)?;
        self.execute(&mut plan).await
    }

    pub async fn transact(&self, step: Transact) -> Result<TransactionResult, PoolError> {
        let mut plan = self.prepare_transact(step);
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| PoolError::Other("transact produced no transaction".into()))
    }

    pub async fn disclose(
        &self,
        req: DisclosureRequest,
    ) -> Result<Option<DisclosureReceipt>, PoolError> {
        let mut sync_waits = 0u32;
        loop {
            let data = self
                .fetcher
                .contracts_data_for_pool(&self.config.pool_contract_id)
                .await
                .map_err(|e| PoolError::Other(format!("fetch chain context: {e:#}")))?;

            let pool = data.pools.into_iter().next().ok_or_else(|| {
                PoolError::Other(format!(
                    "pool {} not found in contract state",
                    self.config.pool_contract_id
                ))
            })?;
            let pool_root = pool
                .merkle_root
                .ok_or_else(|| PoolError::Other("pool merkle_root not fetched".into()))?;
            let pool_next_index = pool
                .merkle_next_index
                .parse::<u32>()
                .map_err(|e| PoolError::Other(format!("invalid pool merkle_next_index: {e}")))?;

            let inputs_req = DisclosureInputsRequest {
                user_address: self.config.user_address.clone(),
                pool_address: self.config.pool_contract_id.clone(),
                selected_commitment: req.selected_commitment,
                pool_root: Some(pool_root),
                pool_next_index,
                tree_depth: pool.merkle_levels,
            };

            match self.storage.build_disclosure_inputs(&inputs_req).await {
                Ok(inputs) => {
                    let context = DisclosureContext {
                        network: self.fetcher.contract_config().network.clone(),
                        pool_address: pool.contract_id,
                        authority_label: req.authority_label,
                        authority_identity_payload_hex: req.authority_identity_payload_hex,
                        purpose: req.purpose,
                        context_nonce: req.context_nonce,
                    };
                    let receipt = self
                        .prover
                        .prove_disclosure(DisclosureProveParams { inputs, context })
                        .await?;
                    return Ok(Some(receipt));
                }
                Err(PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    return Ok(None);
                }
                Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    sync_waits = sync_waits.saturating_add(1);
                    if sync_waits > DISCLOSE_MAX_RETRIES {
                        return Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(
                            gap,
                        )));
                    }
                    sleep(POLL_INTERVAL_MS).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub async fn verify_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<DisclosureVerificationReport, PoolError> {
        verify_disclosure_receipt(
            &self.fetcher,
            self.prover.as_ref(),
            receipt,
            expected_vk_hash,
        )
        .await
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

    // lower level methods

    pub async fn spendable_notes(&self) -> Result<Vec<SpendableNote>, PoolError> {
        self.storage
            .spendable_notes(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    pub fn prepare_deposit(
        &self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.core.prepare_deposit(amount)
    }

    pub fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.core.prepare_transfer(wallet, recipient, amount)
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.core.prepare_withdraw(wallet, amount, recipient)
    }

    pub fn prepare_transact(&self, step: Transact) -> PreparedTransactionPlan {
        PreparedTransactionPlan::from_transact(step)
    }

    pub async fn prove_next(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        self.next_prepared_transaction(plan).await
    }

    pub async fn submit(&self, signed_tx: SignedTransaction) -> Result<String, PoolError> {
        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| PoolError::Other(format!("invalid signed transaction xdr: {e}")))?;

        submit_tx(&envelope, &self.client)
            .await
            .map_err(|e| PoolError::Other(format!("submit transaction: {e:#}")))
    }

    pub async fn confirm(&self, hash: &str) -> Result<TransactionResult, PoolError> {
        const CONFIRM_POLL_ATTEMPTS: u32 = 30;

        let rpc = &self.client;

        for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
            if attempt > 1 {
                sleep(POLL_INTERVAL_MS).await;
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

    pub async fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        self.storage.user_public_keys(user_address).await
    }

    pub async fn sign(
        &self,
        prepared: &PreparedTransaction,
    ) -> Result<SignedTransaction, PoolError> {
        self.signer.sign(prepared).await
    }

    // helpers

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
            let mut prepared = {
                let mut sync_waits = 0u32;
                loop {
                    match self.prove_next(plan).await {
                        Ok(prepared) => break prepared,
                        Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                            sync_waits = sync_waits.saturating_add(1);
                            if sync_waits > SYNC_MAX_RETRIES {
                                return Err(PoolError::MembershipSync(
                                    AspMembershipSync::SyncRequired(gap),
                                ));
                            }
                            sleep(POLL_INTERVAL_MS).await;
                        }
                        Err(error) => return Err(error),
                    }
                }
            };
            self.simulate(&mut prepared).await?;
            let signed = self.sign(&prepared).await?;
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
