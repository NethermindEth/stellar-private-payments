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
    PoolError, TransactionResult, TransferRecipient,
    tx::flows::N_OUTPUTS,
    types::{AspMembershipSync, EncryptionPublicKey, ExtAmount, NoteAmount, NotePublicKey},
};
use tx_planner::{SpendTarget, Transact};
use wasm_bindgen::JsError;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendPlanPreview {
    pub step_count: u32,
}

fn tx_hashes(results: Vec<TransactionResult>) -> Vec<String> {
    results.into_iter().map(|r| r.tx_hash).collect()
}

impl WebClient {
    async fn run_pool_transact(
        &self,
        pool_contract_id: String,
        user_address: String,
        network_passphrase: String,
        on_status: Option<Function>,
        flow: &'static str,
        step: Transact,
    ) -> Result<Option<Vec<String>>, JsError> {
        let pool = self
            .ensure_pool(
                pool_contract_id,
                user_address,
                network_passphrase,
                on_status.clone(),
            )
            .await?;
        emit_progress(
            &on_status,
            flow,
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );
        emit_progress(&on_status, flow, "prove", "Proving…", None, None);

        loop {
            match pool.transact(step.clone()).await {
                Ok(result) => return Ok(Some(vec![result.tx_hash])),
                Err(PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    log::warn!("[{flow}] account should register within ASP");
                    return Ok(None);
                }
                Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    emit_progress(
                        &on_status,
                        flow,
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting to sync {gap} ledger(s) from the chain…")
                        } else {
                            "Waiting to sync ledgers from the chain…".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                }
                Err(error) => return Err(pool_err(error)),
            }
        }
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
            return self
                .run_pool_transact(
                    pool_contract_id,
                    user_address,
                    network_passphrase,
                    on_status,
                    "deposit",
                    step,
                )
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
        emit_progress(
            &on_status,
            "deposit",
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );
        emit_progress(&on_status, "deposit", "prove", "Proving…", None, None);
        loop {
            match pool.deposit(note_amount).await {
                Ok(result) => return Ok(Some(vec![result.tx_hash])),
                Err(PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    log::warn!("[deposit] account should register within ASP");
                    return Ok(None);
                }
                Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    emit_progress(
                        &on_status,
                        "deposit",
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting to sync {gap} ledger(s) from the chain…")
                        } else {
                            "Waiting to sync ledgers from the chain…".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                }
                Err(error) => return Err(pool_err(error)),
            }
        }
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
        emit_progress(
            &on_status,
            flow,
            "sync_check",
            "Checking sync & ASP membership…",
            None,
            None,
        );

        loop {
            let wallet = pool.spendable_notes().await.map_err(pool_err)?;
            let result = match &target {
                SpendTarget::Transfer {
                    recipient_note,
                    recipient_enc,
                } => {
                    let recipient = TransferRecipient {
                        note_public_key: recipient_note.clone(),
                        encryption_public_key: recipient_enc.clone(),
                    };
                    pool.transfer(&wallet, recipient, amount).await
                }
                SpendTarget::Withdraw { recipient } => {
                    pool.withdraw(&wallet, amount, recipient.clone()).await
                }
            };

            match result {
                Ok(results) => return Ok(Some(tx_hashes(results))),
                Err(PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                    log::warn!("[{flow}] account should register within ASP");
                    return Ok(None);
                }
                Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                    emit_progress(
                        &on_status,
                        flow,
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting to sync {gap} ledger(s) from the chain…")
                        } else {
                            "Waiting to sync ledgers from the chain…".to_string()
                        },
                        None,
                        None,
                    );
                    TimeoutFuture::new(1_000).await;
                }
                Err(error) => return Err(pool_err(error)),
            }
        }
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
        let wallet = pool.spendable_notes().await.map_err(pool_err)?;
        let estimate = pool.estimate(&wallet, amount).map_err(pool_err)?;
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

        self.run_pool_transact(
            pool_contract_id,
            user_address,
            network_passphrase,
            on_status,
            flow,
            step,
        )
        .await
    }
}
