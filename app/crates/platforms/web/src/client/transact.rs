//! Pool transaction proving and execution (`deposit`, `transact`, `transfer`,
//! `withdraw`).

use super::{
    emit_progress, parse_ext_amount_decimal, parse_input_note_ids, parse_note_amount_decimal,
    parse_output_amounts, parse_output_recipient_keys, pool::Pool, pool_err,
};
use gloo_timers::future::TimeoutFuture;
use js_sys::{Array, BigInt, Function};
use stellar_private_payments_sdk::{
    PoolError, PreparedTransactionPlan, SpendTarget, Transact, TransferRecipient,
    tx::flows::N_OUTPUTS,
    types::{
        AspMembershipSync, EncryptionPublicKey, Estimate, ExtAmount, NoteAmount, NotePublicKey,
    },
};
use wasm_bindgen::{JsError, prelude::*};

fn execute_hashes_to_js(result: Option<Vec<String>>) -> Result<wasm_bindgen::JsValue, JsError> {
    match result {
        None => Ok(wasm_bindgen::JsValue::NULL),
        Some(hashes) => Ok(serde_wasm_bindgen::to_value(&hashes)?),
    }
}

impl Pool {
    async fn execute_plan(
        &self,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let pool = self.inner();
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

            let simulate_message = if total > 1 {
                format!("Simulating step {current}/{total}…")
            } else {
                "Simulating…".to_string()
            };
            emit_progress(
                on_status,
                flow,
                "simulate",
                simulate_message,
                Some(current),
                Some(total),
            );
            pool.simulate(&mut prepared).await.map_err(pool_err)?;

            let sign_message = if total > 1 {
                format!("Signing step {current}/{total}…")
            } else {
                "Signing…".to_string()
            };
            emit_progress(
                on_status,
                flow,
                "sign",
                sign_message,
                Some(current),
                Some(total),
            );
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
            pool.confirm(&hash).await.map_err(pool_err)?;
            hashes.push(hash);
        }

        Ok(Some(hashes))
    }

    #[allow(clippy::too_many_arguments)]
    async fn deposit_inner(
        &self,
        amount: BigInt,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let pool = self.inner();
        let pool_contract_id = pool.config().pool_contract_id.clone();
        let user_address = pool.config().user_address.clone();

        let ext_amount = parse_ext_amount_decimal(&amount)?;
        if ext_amount <= ExtAmount::ZERO {
            return Err(JsError::new("amount must be > 0 for deposit"));
        }
        let note_amount = NoteAmount::try_from(ext_amount)
            .map_err(|_| JsError::new("deposit amount exceeds note amount range"))?;
        let out_amounts = parse_output_amounts(&output_amounts)?;
        if out_amounts != [note_amount, NoteAmount::ZERO] {
            let (note_pk, enc_pk) = pool
                .user_public_keys(&user_address)
                .await
                .map_err(pool_err)?;
            let step = Transact::new(
                Vec::new(),
                out_amounts,
                ext_amount,
                pool_contract_id,
                [Some(note_pk.clone()), Some(note_pk)],
                [Some(enc_pk.clone()), Some(enc_pk)],
            );
            let mut plan = pool.prepare_transact(step);
            return self.execute_plan(&mut plan, "deposit", on_status).await;
        }

        let mut plan = pool.prepare_deposit(note_amount).map_err(pool_err)?;
        self.execute_plan(&mut plan, "deposit", on_status).await
    }

    async fn spend_inner(
        &self,
        amount: BigInt,
        target: SpendTarget,
        flow: &'static str,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let pool = self.inner();
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

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

        self.execute_plan(&mut plan, flow, on_status).await
    }

    async fn estimate_inner(&self, amount: BigInt) -> Result<Estimate, JsError> {
        let pool = self.inner();
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

        pool.estimate(amount).await.map_err(pool_err)
    }

    #[allow(clippy::too_many_arguments)]
    async fn transact_inner(
        &self,
        ext_recipient: String,
        ext_amount: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        on_status: Option<Function>,
        flow: &'static str,
    ) -> Result<Option<Vec<String>>, JsError> {
        let pool = self.inner();
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

        let mut plan = pool.prepare_transact(step);
        self.execute_plan(&mut plan, flow, on_status).await
    }
}

#[wasm_bindgen]
impl Pool {
    #[wasm_bindgen(js_name = estimate)]
    pub async fn estimate(&self, amount: BigInt) -> Result<wasm_bindgen::JsValue, JsError> {
        let estimate = self.estimate_inner(amount).await?;
        Ok(serde_wasm_bindgen::to_value(&estimate)?)
    }

    #[wasm_bindgen]
    pub async fn deposit(
        &self,
        amount: BigInt,
        output_amounts: Array,
        on_status: Option<Function>,
    ) -> Result<wasm_bindgen::JsValue, JsError> {
        let result = self
            .deposit_inner(amount, output_amounts, on_status)
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen]
    pub async fn transfer(
        &self,
        amount: BigInt,
        recipient_note_key_hex: String,
        recipient_enc_key_hex: String,
        on_status: Option<Function>,
    ) -> Result<wasm_bindgen::JsValue, JsError> {
        let recipient_note = NotePublicKey::parse(&recipient_note_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let recipient_enc = EncryptionPublicKey::parse(&recipient_enc_key_hex)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let target = SpendTarget::transfer(recipient_note, recipient_enc);

        let result = self
            .spend_inner(amount, target, "transfer", on_status)
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen]
    pub async fn withdraw(
        &self,
        withdraw_recipient: String,
        amount: BigInt,
        on_status: Option<Function>,
    ) -> Result<wasm_bindgen::JsValue, JsError> {
        let target = SpendTarget::withdraw(withdraw_recipient);
        let result = self
            .spend_inner(amount, target, "withdraw", on_status)
            .await?;
        execute_hashes_to_js(result)
    }

    #[wasm_bindgen]
    #[allow(clippy::too_many_arguments)]
    pub async fn transact(
        &self,
        ext_recipient: String,
        ext_amount: BigInt,
        input_note_ids: Array,
        output_amounts: Array,
        out_recipient_note_keys_hex: Array,
        out_recipient_enc_keys_hex: Array,
        on_status: Option<Function>,
    ) -> Result<wasm_bindgen::JsValue, JsError> {
        let result = self
            .transact_inner(
                ext_recipient,
                ext_amount,
                input_note_ids,
                output_amounts,
                out_recipient_note_keys_hex,
                out_recipient_enc_keys_hex,
                on_status,
                "transact",
            )
            .await?;
        execute_hashes_to_js(result)
    }
}
