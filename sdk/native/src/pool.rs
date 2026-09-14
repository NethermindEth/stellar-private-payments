//! Async per-pool private payments API

use crate::{
    planner::{SpendableNote, Transact},
    types::{
        EncryptionPublicKey, ExtAmount, ExtData, NoteAmount, NotePublicKey, Sensitive,
        UserNoteSummary,
    },
};

use crate::chain::{Limits, ReadXdr, StateFetcher, TransactionEnvelope, submit_tx};

use crate::{
    PreparedTransaction,
    chain::RpcClient,
    core::{PoolCore, pool_transact_input, transact_step_for_plan},
    correlation::correlation_id_or_new,
    disclosure::{
        DisclosureInputsRequest, DisclosureProveParams, DisclosureRequest,
        verify_disclosure_receipt,
    },
    error::{Error, PlanExecutionError},
    gvk::GvkAudit,
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
        Estimate, Field, GvkMode, PrivatePoolConfig, SignedTransaction, TransactChainContext,
        TransactionResult, TransferRecipient,
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
            .notes(
                &self.config.pool_contract_id,
                self.config.user_address.as_str(),
            )
            .await
    }

    pub async fn estimate(&self, amount: NoteAmount) -> Result<Estimate, Error> {
        let wallet = self.spendable_notes().await?;
        self.core.estimate(&wallet, amount)
    }

    #[tracing::instrument(skip(self), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, Error> {
        tracing::info!(amount = ?Sensitive(amount), "deposit started");
        let mut plan = self.prepare_deposit(amount)?;
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other("deposit produced no transaction".into()))
    }

    #[tracing::instrument(skip(self, recipient), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn transfer(
        &self,
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, Error> {
        let recipient = recipient.into();
        tracing::info!(recipient = ?Sensitive(&recipient), amount = ?Sensitive(amount), "transfer started");
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_transfer(&wallet, recipient, amount).await?;
        self.execute(&mut plan).await
    }

    #[tracing::instrument(skip(self, recipient), fields(correlation_id = %correlation_id_or_new(), amount = ?Sensitive(amount)))]
    pub async fn withdraw(
        &self,
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, Error> {
        let recipient = recipient.into();
        tracing::info!(amount = ?Sensitive(amount), recipient = ?Sensitive(&recipient), "withdraw started");
        let wallet = self.spendable_notes().await?;
        let mut plan = self.prepare_withdraw(&wallet, amount, recipient)?;
        self.execute(&mut plan).await
    }

    #[tracing::instrument(skip(self, step), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn transact(&self, step: Transact) -> Result<TransactionResult, Error> {
        tracing::info!(step = ?Sensitive(&step), "transact started");
        let mut plan = self.prepare_transact(step);
        self.execute(&mut plan)
            .await?
            .pop()
            .ok_or_else(|| Error::Other("transact produced no transaction".into()))
    }

    #[tracing::instrument(skip(self, req), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn disclose(
        &self,
        req: DisclosureRequest,
    ) -> Result<Option<DisclosureReceipt>, Error> {
        tracing::info!(selected_commitments = ?Sensitive(&req.selected_commitments), "disclose started");
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
                user_address: self.config.user_address.as_str().to_string(),
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

    #[tracing::instrument(skip(self, receipt, expected_vk_hash), fields(correlation_id = %correlation_id_or_new()))]
    pub async fn verify_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<DisclosureVerificationReport, Error> {
        tracing::info!(expected_vk_hash = ?Sensitive(expected_vk_hash), "verify_disclosure started");
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
        let input = pool_transact_input(prepared);
        prepared.soroban_tx = match self
            .fetcher
            .prepare_pool_transact(
                &chain_config.pool_contract_id,
                &input,
                // The signing address becomes the contract's `sender`, the
                // sequence-number lookup and the envelope source.
                &chain_config.signer_address,
            )
            .await
        {
            Ok(tx) => tx,
            Err(e) => {
                let detail = format!("{e:#}");
                return Err(self.simulation_error(&input.ext_data, detail));
            }
        };

        Ok(())
    }

    fn simulation_error(&self, ext_data: &ExtData, detail: String) -> Error {
        let token = self
            .config
            .contract_config
            .pool(&self.config.pool_contract_id)
            .map(|pool| pool.token_contract_id.as_str())
            .unwrap_or_default();
        classify_simulation_failure(ext_data, token, detail)
    }

    pub async fn audit(&self, global_view_private_key: Field) -> Result<GvkAudit<S>, Error> {
        let pool = self
            .config
            .contract_config
            .pool(&self.config.pool_contract_id)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        if pool.gvk_mode == GvkMode::Off {
            return Err(Error::InvalidConfig(format!(
                "GVK audit requires a pool-gvk deployment; {} is configured with gvk_mode Off",
                self.config.pool_contract_id
            )));
        }
        crate::types::validate_gvk_authority_key(&global_view_private_key, pool)
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        self.ensure_synced().await?;

        let storage = self.storage.fork()?;
        let pool_contract_id = self.config.pool_contract_id.clone();
        Ok(GvkAudit::new(
            storage,
            pool_contract_id,
            global_view_private_key,
        ))
    }

    // lower level methods

    pub async fn spendable_notes(&self) -> Result<Vec<SpendableNote>, Error> {
        self.ensure_synced().await?;
        self.storage
            .spendable_notes(
                &self.config.pool_contract_id,
                self.config.user_address.as_str(),
            )
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
            self.config.user_address.as_str(),
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
            .user_public_keys(self.config.user_address.as_str())
            .await?;
        self.fetcher
            .transact_chain_context(
                &self.config.pool_contract_id,
                &note_pub,
                self.config.user_address.as_str(),
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
            let step_index = results.len();
            tracing::info!(step_index, "execute plan step");
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
                Ok(hash) => {
                    tracing::info!(hash, "transaction submitted");
                    hash
                }
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            let result = match self.confirm(&hash).await {
                Ok(result) => {
                    tracing::info!(hash, "transaction confirmed");
                    result
                }
                Err(error) => return Err(PlanExecutionError::into_error(results, error)),
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn deposit_transact_step(&self, amount: NoteAmount) -> Result<Transact, Error> {
        let (note_pub, enc_pub) = self
            .storage
            .user_public_keys(self.config.user_address.as_str())
            .await?;
        self.core.deposit_transact_step(note_pub, enc_pub, amount)
    }
}

/// Name the recipient when simulation failed on the payout.
///
/// A withdrawal's only token movement is the transfer to `ext_data.recipient`
/// (`contracts/pool/src/pool.rs:535`). What the RPC returns is a host error and
/// a page of diagnostics naming neither the recipient nor the reason.
///
/// Claiming a recipient is at fault when it is not would send someone to fund
/// an address that was never the problem, so the bar is deliberately high: the
/// asset contract must be the contract that raised the error, and that error
/// must state a condition only the recipient can be in. A transfer the pool
/// could not fund, a failure anywhere after the payout, and anything else keep
/// the raw message — the asset contract appears in the event log of a
/// *successful* transfer too, so its presence alone means nothing.
fn classify_simulation_failure(
    ext_data: &ExtData,
    token_contract_id: &str,
    detail: String,
) -> Error {
    if ext_data.ext_amount < ExtAmount::ZERO
        && recipient_was_refused(&detail, token_contract_id).is_some()
    {
        return Error::RecipientCannotReceive {
            recipient: ext_data.recipient.clone(),
            simulation: detail,
        };
    }
    Error::Other(format!("simulate transaction: {detail}"))
}

/// Conditions in the asset contract that only the recipient can be in.
///
/// Kept to what has been observed rather than guessed: the first is what
/// testnet returns for a payout to an address that is not an account yet
/// (creating one costs more than the payout), the second is how the classic
/// asset contract speaks about a missing or insufficient trustline. Anything
/// not listed here is not attributed to the recipient.
const RECIPIENT_REFUSALS: &[&str] = &["below minimum balance for new account", "trustline"];

/// The asset contract's own error event, when it names a recipient-side cause.
///
/// Diagnostics arrive one event per line, so the error event and its data have
/// to be found on the same line: a `fn_call` to the asset contract that
/// succeeded sits on a different line from whatever failed afterwards.
fn recipient_was_refused<'a>(detail: &'a str, token_contract_id: &str) -> Option<&'a str> {
    if token_contract_id.is_empty() {
        return None;
    }
    detail.lines().find(|line| {
        line.contains(&format!("contract:{token_contract_id}"))
            && line.contains("topics:[error")
            && RECIPIENT_REFUSALS.iter().any(|cause| line.contains(cause))
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod simulation_failure_tests {
    use super::*;

    const POOL: &str = "CD2W5LURL6GXAJTZVADMRVZPXIZTTPJH5TBMMQ5G4A6XPCMUJ2OHXZ4L";
    const TOKEN: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";
    const RECIPIENT: &str = "GBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB6BQ";

    fn ext_data(ext_amount: i128) -> ExtData {
        ExtData {
            recipient: RECIPIENT.to_string(),
            ext_amount: ExtAmount::from(ext_amount),
            encrypted_output0: Vec::new(),
            encrypted_output1: Vec::new(),
        }
    }

    /// The shape the RPC actually returns: a host error, then diagnostics in
    /// which the asset contract is the one that trapped.
    fn payout_failure() -> String {
        format!(
            "transaction simulation failed: HostError: Error(Contract, #14)\n\n\
             Event log (newest first):\n   \
             0: [Failed Diagnostic Event (not emitted)] contract:{TOKEN}, topics:[error, \
             Error(Contract, #14)], data:[\"transfer amount is below minimum balance for new \
             account\", 500000, 10000000]"
        )
    }

    #[test]
    fn a_withdrawal_that_trapped_in_the_asset_contract_names_the_recipient() {
        let error = classify_simulation_failure(&ext_data(-500_000), TOKEN, payout_failure());
        match &error {
            Error::RecipientCannotReceive {
                recipient,
                simulation,
            } => {
                assert_eq!(recipient, RECIPIENT);
                assert!(simulation.contains("Error(Contract, #14)"));
            }
            other => panic!("expected RecipientCannotReceive, got {other:?}"),
        }
    }

    /// Only a withdrawal pays a recipient. A deposit also touches the asset
    /// contract, and its failure is the sender's problem, not a recipient's.
    #[test]
    fn a_deposit_that_trapped_in_the_asset_contract_is_not_a_recipient_problem() {
        let error = classify_simulation_failure(&ext_data(500_000), TOKEN, payout_failure());
        assert!(matches!(error, Error::Other(_)), "got {error:?}");
    }

    /// The asset contract is in the event log of a *successful* transfer too.
    /// A withdrawal that paid out and then failed while recording the spend is
    /// not the recipient's doing, and must not tell anyone to fund it.
    #[test]
    fn a_failure_after_the_payout_is_not_blamed_on_the_recipient() {
        let detail = format!(
            "transaction simulation failed: HostError: Error(Storage, #5)\n\n\
             Event log (newest first):\n   \
             0: [Diagnostic Event] contract:{POOL}, topics:[error, Error(Storage, #5)], \
             data:\"trying to access past-the-end entry\"\n   \
             1: [Diagnostic Event] contract:{POOL}, topics:[fn_return, transfer], data:Void\n   \
             2: [Diagnostic Event] contract:{POOL}, topics:[fn_call, {TOKEN}, transfer], \
             data:[{POOL}, {RECIPIENT}, 500000]"
        );
        let error = classify_simulation_failure(&ext_data(-500_000), TOKEN, detail);
        assert!(matches!(error, Error::Other(_)), "got {error:?}");
    }

    /// The asset contract refusing because the *pool* cannot cover the payout
    /// is a pool problem. Same contract, same call, different party.
    #[test]
    fn a_payout_the_pool_cannot_fund_is_not_blamed_on_the_recipient() {
        let detail = format!(
            "transaction simulation failed: HostError: Error(Contract, #10)\n\n\
             Event log (newest first):\n   \
             0: [Failed Diagnostic Event (not emitted)] contract:{TOKEN}, topics:[error, \
             Error(Contract, #10)], data:[\"insufficient balance\", 400000, 500000]"
        );
        let error = classify_simulation_failure(&ext_data(-500_000), TOKEN, detail);
        assert!(matches!(error, Error::Other(_)), "got {error:?}");
    }

    /// The classic-asset half of the same condition.
    #[test]
    fn a_recipient_without_a_trustline_is_named() {
        let detail = format!(
            "transaction simulation failed: HostError: Error(Contract, #13)\n\n\
             Event log (newest first):\n   \
             0: [Failed Diagnostic Event (not emitted)] contract:{TOKEN}, topics:[error, \
             Error(Contract, #13)], data:[\"trustline missing for account\", {RECIPIENT}]"
        );
        let error = classify_simulation_failure(&ext_data(-500_000), TOKEN, detail);
        assert!(
            matches!(error, Error::RecipientCannotReceive { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn a_failure_elsewhere_in_the_pool_keeps_its_own_message() {
        let detail = "transaction simulation failed: HostError: Error(Contract, #3)".to_string();
        let error = classify_simulation_failure(&ext_data(-500_000), TOKEN, detail.clone());
        match &error {
            Error::Other(message) => assert!(message.contains(&detail)),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    /// The message reaches a UI toast, where a cancellation classifier matches
    /// on substrings. A payout that cannot land is not a cancellation.
    #[test]
    fn the_message_does_not_read_as_a_wallet_cancellation() {
        let rendered = classify_simulation_failure(&ext_data(-500_000), TOKEN, payout_failure())
            .to_string()
            .to_ascii_lowercase();
        for word in ["rejected", "denied", "cancelled", "canceled"] {
            assert!(!rendered.contains(word), "{word:?} in: {rendered}");
        }
    }
}
