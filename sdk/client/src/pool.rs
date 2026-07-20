//! Async per-pool private payments API

use tx_planner::{SpendableNote, Transact};
use types::{EncryptionPublicKey, NoteAmount, NotePublicKey, UserNoteSummary};

use stellar::{Limits, ReadXdr, StateFetcher, TransactionEnvelope, submit_tx};

use crate::{
    PoolCore, PreparedTransaction,
    chain::RpcClient,
    core::{pool_transact_input, transact_step_for_plan},
    disclosure::{
        DisclosureInputsRequest, DisclosureProveParams, DisclosureRequest,
        verify_disclosure_receipt,
    },
    error::{Error, PlanExecutionError},
    handle::Handle,
    plan::PreparedTransactionPlan,
    prover::Prover,
    signer::Signer,
    sleep::sleep,
    storage::Storage,
    sync::{SyncHandle, confirm_tx},
    transact::transact_request_from_step,
    types::{
        AspMembershipSync, DisclosureContext, DisclosureReceipt, DisclosureVerificationReport,
        Estimate, PrivatePoolConfig, SignedTransaction, TransactChainContext, TransactionResult,
        TransferRecipient,
    },
};

const POLL_INTERVAL_MS: u32 = 200;
const SYNC_MAX_RETRIES: u32 = 50;
const DISCLOSE_MAX_RETRIES: u32 = 50;

/// Main entry point for a single privacy pool.
///
/// Construct via [`crate::Account::pool`].
pub struct PrivatePool<S> {
    rpc: RpcClient,
    config: PrivatePoolConfig,
    core: PoolCore,
    fetcher: StateFetcher,
    storage: S,
    prover: Handle<dyn Prover>,
    signer: Handle<dyn Signer>,
    sync: SyncHandle,
}

impl<S> PrivatePool<S> {
    pub(crate) fn init(
        rpc: RpcClient,
        config: PrivatePoolConfig,
        storage: S,
        signer: Handle<dyn Signer>,
        prover: Handle<dyn Prover>,
        sync: SyncHandle,
    ) -> Result<Self, Error> {
        config.validate()?;
        let fetcher = StateFetcher::new(rpc.clone(), config.contract_config.clone())
            .map_err(|e| Error::Other(format!("state fetcher: {e:#}")))?;
        Ok(Self {
            rpc,
            core: PoolCore::new(config.clone())?,
            config,
            fetcher,
            storage,
            prover,
            signer,
            sync,
        })
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }
}

impl<S: Storage> PrivatePool<S> {
    // high level methods

    pub async fn balance(&self) -> Result<NoteAmount, Error> {
        let wallet = self.spendable_notes().await?;
        wallet
            .iter()
            .map(|note| note.amount)
            .try_fold(NoteAmount::ZERO, |sum, amount| {
                sum.checked_add(amount)
                    .ok_or_else(|| Error::Other("wallet balance overflow".into()))
            })
    }

    pub async fn notes(&self) -> Result<Vec<UserNoteSummary>, Error> {
        self.ensure_synced().await?;
        self.storage
            .notes(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    pub async fn estimate(&self, amount: NoteAmount) -> Result<Estimate, Error> {
        let wallet = self.spendable_notes().await?;
        self.core.estimate(&wallet, amount)
    }

    pub async fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, Error> {
        let mut plan = self.prepare_deposit(amount)?;
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other("deposit produced no transaction".into()))
    }

    pub async fn transfer(
        &self,
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, Error> {
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_transfer(&wallet, recipient, amount).await?;
        self.execute(&mut plan).await
    }

    pub async fn withdraw(
        &self,
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, Error> {
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_withdraw(&wallet, amount, recipient)?;
        self.execute(&mut plan).await
    }

    pub async fn transact(&self, step: Transact) -> Result<TransactionResult, Error> {
        let mut plan = self.prepare_transact(step);
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other("transact produced no transaction".into()))
    }

    pub async fn disclose(
        &self,
        req: DisclosureRequest,
    ) -> Result<Option<DisclosureReceipt>, Error> {
        if req.selected_commitments.is_empty() || req.selected_commitments.len() > 4 {
            return Err(Error::Other(
                "selective disclosure requires 1..=4 selected commitments".into(),
            ));
        }

        let selected_commitments = req.selected_commitments;
        let mut sync_waits = 0u32;
        loop {
            let data = self
                .fetcher
                .contracts_data_for_pool(&self.config.pool_contract_id)
                .await
                .map_err(|e| Error::Other(format!("fetch chain context: {e:#}")))?;

            let pool = data.pools.into_iter().next().ok_or_else(|| {
                Error::Other(format!(
                    "pool {} not found in contract state",
                    self.config.pool_contract_id
                ))
            })?;
            let pool_root = pool
                .merkle_root
                .ok_or_else(|| Error::Other("pool merkle_root not fetched".into()))?;
            let pool_next_index = pool
                .merkle_next_index
                .parse::<u32>()
                .map_err(|e| Error::Other(format!("invalid pool merkle_next_index: {e}")))?;

            let inputs_req = DisclosureInputsRequest {
                user_address: self.config.user_address.clone(),
                pool_address: self.config.pool_contract_id.clone(),
                selected_commitments: selected_commitments.clone(),
                pool_root: Some(pool_root),
                pool_next_index,
                tree_depth: pool.merkle_levels,
            };

            match self.storage.build_disclosure_inputs(&inputs_req).await {
                Ok(notes) => {
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
                        .prove_disclosure(DisclosureProveParams { notes, context })
                        .await?;
                    return Ok(Some(receipt));
                }
                Err(Error::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    return Ok(None);
                }
                Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    sync_waits = sync_waits.saturating_add(1);
                    if sync_waits > DISCLOSE_MAX_RETRIES {
                        return Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap)));
                    }
                    self.ensure_synced().await?;
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
    ) -> Result<DisclosureVerificationReport, Error> {
        verify_disclosure_receipt(
            &self.fetcher,
            self.prover.as_ref(),
            receipt,
            expected_vk_hash,
        )
        .await
    }

    pub async fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), Error> {
        let chain_config = self.core.config();
        prepared.soroban_tx = self
            .fetcher
            .prepare_pool_transact(
                &chain_config.pool_contract_id,
                &pool_transact_input(prepared),
                &chain_config.user_address,
            )
            .await
            .map_err(|e| Error::Other(format!("simulate transaction: {e:#}")))?;

        Ok(())
    }

    // lower level methods

    pub async fn spendable_notes(&self) -> Result<Vec<SpendableNote>, Error> {
        self.ensure_synced().await?;
        self.storage
            .spendable_notes(&self.config.pool_contract_id, &self.config.user_address)
            .await
    }

    pub fn prepare_deposit(&self, amount: NoteAmount) -> Result<PreparedTransactionPlan, Error> {
        self.core.prepare_deposit(amount)
    }

    pub async fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        let (note_public_key, encryption_public_key) =
            self.resolve_transfer_recipient(recipient.into()).await?;
        self.core
            .prepare_transfer(wallet, note_public_key, encryption_public_key, amount)
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, Error> {
        self.core.prepare_withdraw(wallet, amount, recipient)
    }

    pub fn prepare_transact(&self, step: Transact) -> PreparedTransactionPlan {
        PreparedTransactionPlan::from_transact(step)
    }

    pub async fn prove_next(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, Error> {
        self.next_prepared_transaction(plan).await
    }

    pub async fn submit(&self, signed_tx: SignedTransaction) -> Result<String, Error> {
        let envelope = TransactionEnvelope::from_xdr_base64(&signed_tx.signed_xdr, Limits::none())
            .map_err(|e| Error::Other(format!("invalid signed transaction xdr: {e}")))?;

        submit_tx(&self.rpc, &envelope)
            .await
            .map_err(|e| Error::Other(format!("submit transaction: {e:#}")))
    }

    pub async fn confirm(&self, hash: &str) -> Result<TransactionResult, Error> {
        confirm_tx(&self.rpc, hash).await
    }

    pub async fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, Error> {
        self.signer.sign_transaction(prepared).await
    }

    // helpers

    async fn ensure_synced(&self) -> Result<(), Error> {
        self.sync
            .ensure_synced(&self.rpc, &self.storage, &self.config.contract_config)
            .await
    }

    async fn resolve_transfer_recipient(
        &self,
        recipient: TransferRecipient,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        match recipient {
            TransferRecipient::Keys {
                note_public_key,
                encryption_public_key,
            } => Ok((note_public_key, encryption_public_key)),
            TransferRecipient::Address(address) => {
                self.ensure_synced().await?;
                self.storage
                    .registered_public_keys(
                        &address,
                        &self.config.contract_config.public_key_registry,
                    )
                    .await
            }
        }
    }

    async fn next_prepared_transaction(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, Error> {
        if plan.is_complete() {
            return Err(Error::Other("transaction plan is complete".into()));
        }
        self.ensure_synced().await?;

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

    async fn fetch_transact_chain_context(&self) -> Result<TransactChainContext, Error> {
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
            .map_err(|e| Error::Other(format!("fetch chain context: {e:#}")))
    }

    async fn execute(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<Vec<TransactionResult>, Error> {
        let mut results = Vec::new();
        while !plan.is_complete() {
            let mut prepared = {
                let mut sync_waits = 0u32;
                loop {
                    match self.prove_next(plan).await {
                        Ok(prepared) => break prepared,
                        Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                            sync_waits = sync_waits.saturating_add(1);
                            if sync_waits > SYNC_MAX_RETRIES {
                                return Err(PlanExecutionError::into_error(
                                    results,
                                    Error::MembershipSync(AspMembershipSync::SyncRequired(gap)),
                                ));
                            }
                            if let Err(error) = self.ensure_synced().await {
                                return Err(PlanExecutionError::into_error(results, error));
                            }
                            sleep(POLL_INTERVAL_MS).await;
                        }
                        Err(error) => return Err(PlanExecutionError::into_error(results, error)),
                    }
                }
            };
            if let Err(error) = self.simulate(&mut prepared).await {
                return Err(PlanExecutionError::into_error(results, error));
            }
            let signed = match self.sign(&prepared).await {
                Ok(signed) => signed,
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            let hash = match self.submit(signed).await {
                Ok(hash) => hash,
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            let result = match self.confirm(&hash).await {
                Ok(result) => result,
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, Error> {
        let (note_pub, enc_pub) = self
            .storage
            .user_public_keys(&self.config.user_address)
            .await?;
        self.core.deposit_transact_step(note_pub, enc_pub, amount)
    }
}
