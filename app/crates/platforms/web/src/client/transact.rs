//! Pool transaction proving and execution (`executeDeposit`, `executeTransact`,
//! `executeTransfer`, `executeWithdraw`).

use super::{
    WebClient, emit_progress, parse_ext_amount_decimal, parse_input_note_ids,
    parse_note_amount_decimal, parse_output_amounts, parse_output_recipient_keys, pool_err,
};
use crate::protocol::{StorageWorkerRequest, StorageWorkerResponse};
use gloo_timers::future::TimeoutFuture;
use js_sys::{Array, BigInt, Function};
use serde::Serialize;
use stellar_private_payments_sdk::{
    PoolError, PreparedTransactionPlan, PrivatePool, TransactionResult, TransferRecipient,
    tx::flows::N_OUTPUTS,
    types::{AspMembershipSync, EncryptionPublicKey, ExtAmount, NoteAmount, NotePublicKey},
};
use tx_planner::{SpendTarget, Transact};
use wasm_bindgen::JsError;

use crate::workers::storage::StorageBridge;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendPlanPreview {
    pub step_count: u32,
}

fn tx_hashes(results: Vec<TransactionResult>) -> Vec<String> {
    results.into_iter().map(|r| r.tx_hash).collect()
}

impl WebClient {
    async fn execute_plan(
        &self,
        pool: &PrivatePool<StorageBridge>,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        self.set_signer_flow(flow);
        let on_status = &on_status;
        let total = plan.tx_count();
        let mut hashes = Vec::new();

        while !plan.is_complete() {
            let current = plan.current_tx().saturating_add(1);

            let mut prepared = loop {
                let prove_message = if total > 1 {
                    format!("Proving step {current}/{total}…")
                } else {
                    "Proving…".to_string()
                };
                emit_progress(
                    on_status,
                    flow,
                    "prove",
                    prove_message,
                    Some(current),
                    Some(total),
                );

                match pool.prove_next(plan).await {
                    Ok(prepared) => break prepared,
                    Err(PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                        log::warn!("[{flow}] account should register within ASP");
                        return Ok(None);
                    }
                    Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                        log::info!("[{flow}] sync is needed - waiting the indexer");
                        emit_progress(
                            on_status,
                            flow,
                            "sync_wait",
                            if let Some(gap) = gap {
                                format!("Waiting to sync {gap} ledger(s) from the chain…")
                            } else {
                                "Waiting to sync ledgers from the chain…".to_string()
                            },
                            Some(current),
                            Some(total),
                        );
                        TimeoutFuture::new(1_000).await;
                    }
                    Err(error) => return Err(pool_err(error)),
                }
            };

            pool.simulate(&mut prepared).await.map_err(pool_err)?;
            let signed = pool.sign(&prepared).await.map_err(pool_err)?;

            let submit_message = if total > 1 {
                format!("Submitting step {current}/{total}…")
            } else {
                "Submitting…".to_string()
            };
            emit_progress(
                on_status,
                flow,
                "submit",
                submit_message,
                Some(current),
                Some(total),
            );
            let hash = pool.submit(signed).await.map_err(pool_err)?;
            self.confirm_with_progress(&hash, flow, on_status).await?;
            hashes.push(hash);
        }

        Ok(Some(hashes))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_deposit_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
        output_amounts: Array,
        network_passphrase: String,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let ext_amount = parse_ext_amount_decimal(&amount)?;
        if ext_amount <= ExtAmount::ZERO {
            return Err(JsError::new("amount must be > 0 for deposit"));
        }
        let note_amount = NoteAmount::try_from(ext_amount)
            .map_err(|_| JsError::new("deposit amount exceeds note amount range"))?;
        let out_amounts = parse_output_amounts(&output_amounts)?;
        if out_amounts != [note_amount, NoteAmount::ZERO] {
            let keys = match self
                .storage_request(StorageWorkerRequest::UserKeys(user_address.clone()), 1_000)
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage response loading user keys: {:?}",
                        other
                    )));
                }
            };
            let note_pk: NotePublicKey = keys.note_keypair.public;
            let enc_pk: EncryptionPublicKey = keys.encryption_keypair.public;
            let step = Transact::new(
                Vec::new(),
                out_amounts,
                ext_amount,
                pool_contract_id.clone(),
                [Some(note_pk.clone()), Some(note_pk)],
                [Some(enc_pk.clone()), Some(enc_pk)],
            );
            let pool = self
                .ensure_pool(
                    pool_contract_id,
                    user_address,
                    network_passphrase,
                    on_status.clone(),
                )
                .await?;
            let mut plan = pool.prepare_transact(step);
            return self
                .execute_plan(&pool, &mut plan, "deposit", on_status)
                .await;
        }

        let pool = self
            .ensure_pool(
                pool_contract_id,
                user_address,
                network_passphrase,
                on_status.clone(),
            )
            .await?;
        let mut plan = pool.prepare_deposit(note_amount).map_err(pool_err)?;
        self.execute_plan(&pool, &mut plan, "deposit", on_status)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_spend_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
        target: SpendTarget,
        flow: &'static str,
        network_passphrase: String,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

        let pool = self
            .ensure_pool(
                pool_contract_id,
                user_address,
                network_passphrase,
                on_status.clone(),
            )
            .await?;
        let wallet = pool.spendable_notes().await.map_err(pool_err)?;
        let mut plan = match &target {
            SpendTarget::Transfer {
                recipient_note,
                recipient_enc,
            } => {
                let recipient = TransferRecipient {
                    note_public_key: recipient_note.clone(),
                    encryption_public_key: recipient_enc.clone(),
                };
                pool.prepare_transfer(&wallet, recipient, amount)
            }
            SpendTarget::Withdraw { recipient } => {
                pool.prepare_withdraw(&wallet, amount, recipient.clone())
            }
        }
        .map_err(pool_err)?;

        self.execute_plan(&pool, &mut plan, flow, on_status).await
    }

    pub(super) async fn plan_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
        network_passphrase: String,
    ) -> Result<SpendPlanPreview, JsError> {
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

        let pool = self
            .ensure_pool(pool_contract_id, user_address, network_passphrase, None)
            .await?;
        let estimate = pool.plan(amount).await.map_err(pool_err)?;
        Ok(SpendPlanPreview {
            step_count: estimate.tx_count,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_transact_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        ext_recipient: String,
        ext_amount: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        network_passphrase: String,
        on_status: Option<Function>,
        flow: &'static str,
    ) -> Result<Option<Vec<String>>, JsError> {
        let expected_outputs =
            u32::try_from(N_OUTPUTS).map_err(|_| JsError::new("N_OUTPUTS exceeds u32"))?;
        if out_recipient_note_keys_hex.length() != expected_outputs {
            return Err(JsError::new(&format!(
                "out_recipient_note_keys_hex must have length {N_OUTPUTS}"
            )));
        }
        if out_recipient_enc_keys_hex.length() != expected_outputs {
            return Err(JsError::new(&format!(
                "out_recipient_enc_keys_hex must have length {N_OUTPUTS}"
            )));
        }

        let ext_amount = parse_ext_amount_decimal(&ext_amount)?;
        let input_commitments = parse_input_note_ids(
            &input_note_ids,
            0,
            2,
            "input_note_ids must have length 0..=2",
        )?;
        let out_amounts = parse_output_amounts(&output_amounts)?;
        let (out_note_pks, out_enc_pks) =
            parse_output_recipient_keys(&out_recipient_note_keys_hex, &out_recipient_enc_keys_hex)?;

        let step = Transact::new(
            input_commitments,
            out_amounts,
            ext_amount,
            ext_recipient,
            out_note_pks,
            out_enc_pks,
        );

        let pool = self
            .ensure_pool(
                pool_contract_id,
                user_address,
                network_passphrase,
                on_status.clone(),
            )
            .await?;
        let mut plan = pool.prepare_transact(step);
        self.execute_plan(&pool, &mut plan, flow, on_status).await
    }
}
