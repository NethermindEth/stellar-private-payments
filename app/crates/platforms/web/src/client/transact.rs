//! Pool `transact` proving and planned multi-step execution (`executeTransfer`
//! / `executeWithdraw`).

use super::{
    WebClient, emit_progress, parse_field_bigint_numeric, parse_note_amount_decimal,
    parse_u32_decimal,
};
use crate::protocol::{
    PreparedProverTx, ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest,
    StorageWorkerResponse, TransactRequest,
};
use gloo_timers::future::TimeoutFuture;
use js_sys::{BigInt, Function, Promise};
use serde::Serialize;
use tx_planner::{SpendSession, SpendSessionError, SpendTarget, SpendableNote, Transact, plan};
use types::{AspMembershipSync, ContractsStateData, Field, NotePublicKey, SMT_DEPTH};
use wasm_bindgen::{JsCast, JsError, JsValue};
use wasm_bindgen_futures::JsFuture;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendPlanPreview {
    pub step_count: u32,
}

fn spend_session_err(e: SpendSessionError) -> JsError {
    JsError::new(&e.to_string())
}

impl WebClient {
    pub(super) async fn load_spendable_wallet(
        &self,
        pool_contract_id: &str,
        address: &str,
    ) -> Result<Vec<SpendableNote>, JsError> {
        let resp = self
            .storage_request(
                StorageWorkerRequest::UnspentUserNotes {
                    user_address: address.to_string(),
                    pool_contract_id: pool_contract_id.to_string(),
                },
                5_000,
            )
            .await?;
        let notes = match resp {
            StorageWorkerResponse::UserNotes(list) => list,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected storage response loading notes: {:?}",
                    other
                )));
            }
        };
        Ok(notes
            .into_iter()
            .map(|n| SpendableNote {
                commitment: n.id,
                amount: n.amount,
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn prove_transact_inner(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        membership_blinding: Field,
        step: &Transact,
        flow: &'static str,
        on_status: &Option<Function>,
        step_current: Option<u32>,
        step_total: Option<u32>,
    ) -> Result<Option<PreparedProverTx>, JsError> {
        emit_progress(
            on_status,
            flow,
            "sync_check",
            "Checking sync & ASP membership…",
            step_current,
            step_total,
        );

        let params = loop {
            emit_progress(
                on_status,
                flow,
                "fetch_chain_state",
                "Fetching on-chain state…",
                step_current,
                step_total,
            );
            let ContractsStateData {
                pools,
                asp_membership,
                asp_non_membership,
            } = self
                .fetcher
                .contracts_data_for_pool(pool_contract_id)
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let pool = pools
                .into_iter()
                .next()
                .ok_or_else(|| JsError::new("the pool data is not fetched"))?;
            let pool_root = pool.merkle_root;
            let pool_next_index =
                parse_u32_decimal(&pool.merkle_next_index).map_err(|e| JsError::new(&e))?;

            emit_progress(
                on_status,
                flow,
                "load_state",
                "Loading local keys…",
                step_current,
                step_total,
            );
            let keys = match self
                .storage_request(
                    StorageWorkerRequest::UserKeys(user_address.to_string()),
                    1_000,
                )
                .await?
            {
                StorageWorkerResponse::UserKeys(keys) => {
                    keys.ok_or_else(|| JsError::new("user keys not found in worker storage"))?
                }
                other => return Err(JsError::new(&format!("Unexpected response: {:?}", other))),
            };
            let note_pubkey: NotePublicKey = keys.note_keypair.public;

            emit_progress(
                on_status,
                flow,
                "fetch_chain_state",
                "Fetching ASP non-membership proof…",
                step_current,
                step_total,
            );
            let non_membership_proof = self
                .fetcher
                .get_nonmembership_proof(
                    &note_pubkey,
                    asp_non_membership.root,
                    SMT_DEPTH as usize,
                    user_address,
                )
                .await
                .map_err(|e| JsError::new(&e.to_string()))?;

            let req = TransactRequest {
                user_address: user_address.to_string(),
                membership_blinding,
                pool_root,
                pool_next_index,
                pool_address: pool.contract_id,
                ext_recipient: step.ext_recipient.clone(),
                ext_amount: step.ext_amount,
                aspmem_root: asp_membership.root,
                aspmem_contract_id: asp_membership.contract_id.clone(),
                aspmem_ledger: asp_membership.ledger,
                input_commitments: step.input_commitments.clone(),
                output_amounts: step.output_amounts,
                out_recipient_note_pubkeys: step.out_recipient_note_pubkeys.clone(),
                out_recipient_encryption_pubkeys: step.out_recipient_encryption_pubkeys.clone(),
                smt_depth: SMT_DEPTH,
                tree_depth: pool.merkle_levels,
                non_membership_proof,
            };

            emit_progress(
                on_status,
                flow,
                "load_state",
                "Building witness inputs…",
                step_current,
                step_total,
            );
            match self
                .storage_request(StorageWorkerRequest::Transact(req), 5_000)
                .await?
            {
                StorageWorkerResponse::TransactParams(p) => break p,
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::RegisterAtASP) => {
                    log::warn!("[{flow}] the account {user_address} should register within ASP");
                    return Ok(None);
                }
                StorageWorkerResponse::AspMembershipSync(AspMembershipSync::SyncRequired(gap)) => {
                    log::info!("[{flow}] sync is needed - waiting the indexer");
                    emit_progress(
                        on_status,
                        flow,
                        "sync_wait",
                        if let Some(gap) = gap {
                            format!("Waiting to sync {gap} ledger(s) from the chain...")
                        } else {
                            "Waiting to sync ledgers from the chain...".to_string()
                        },
                        step_current,
                        step_total,
                    );
                    TimeoutFuture::new(1_000).await;
                    continue;
                }
                other => {
                    return Err(JsError::new(&format!(
                        "Unexpected storage worker response: {:?}",
                        other
                    )));
                }
            }
        };

        let prove_message = match (step_current, step_total) {
            (Some(current), Some(total)) => format!("Proving step {current}/{total}…"),
            _ => "Proving…".to_string(),
        };
        emit_progress(
            on_status,
            flow,
            "prove",
            prove_message,
            step_current,
            step_total,
        );
        self.ping_prover()
            .await
            .map_err(|e| JsError::new(&format!("failed to load prover: {e:?}")))?;

        let prepared = match self
            .prover_request(ProverWorkerRequest::Transact(params), 20_000)
            .await?
        {
            ProverWorkerResponse::TransactPrepared(p) => p,
            other => {
                return Err(JsError::new(&format!(
                    "Unexpected prover worker response: {:?}",
                    other
                )));
            }
        };

        Ok(Some(prepared))
    }

    async fn call_js_submit(
        submit_fn: &Function,
        proved: &PreparedProverTx,
    ) -> Result<String, JsError> {
        let proved_js =
            serde_wasm_bindgen::to_value(proved).map_err(|e| JsError::new(&e.to_string()))?;
        let promise_val = submit_fn
            .call1(&JsValue::NULL, &proved_js)
            .map_err(|e| JsError::new(&format!("submit callback failed: {e:?}")))?;
        if promise_val.is_null() || promise_val.is_undefined() {
            return Err(JsError::new("submit callback must return a Promise"));
        }
        let promise: Promise = promise_val
            .dyn_into()
            .map_err(|_| JsError::new("submit callback must return a Promise"))?;
        let result = JsFuture::from(promise)
            .await
            .map_err(|e| JsError::new(&format!("submit callback rejected: {e:?}")))?;
        result.as_string().ok_or_else(|| {
            JsError::new("submit callback must resolve to a transaction hash string")
        })
    }

    pub(super) async fn plan_spend_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        amount: BigInt,
    ) -> Result<SpendPlanPreview, JsError> {
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

        let wallet = self
            .load_spendable_wallet(&pool_contract_id, &user_address)
            .await?;
        let tx_plan = plan(amount, &wallet).map_err(|e| JsError::new(&e.to_string()))?;
        let step_count = u32::try_from(tx_plan.len())
            .map_err(|_| JsError::new("plan produces too many steps for u32"))?;
        Ok(SpendPlanPreview { step_count })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn execute_spend_inner(
        &self,
        pool_contract_id: String,
        user_address: String,
        membership_blinding: BigInt,
        amount: BigInt,
        target: SpendTarget,
        flow: &'static str,
        submit_fn: Function,
        on_status: Option<Function>,
    ) -> Result<Option<Vec<String>>, JsError> {
        let membership_blinding = parse_field_bigint_numeric(&membership_blinding)?;
        let amount = parse_note_amount_decimal(&amount)?;
        if amount.is_zero() {
            return Err(JsError::new("amount must be > 0"));
        }

        let wallet = self
            .load_spendable_wallet(&pool_contract_id, &user_address)
            .await?;
        let mut session = SpendSession::setup(wallet, amount, pool_contract_id.clone(), target)
            .map_err(spend_session_err)?;

        let total_u32 = u32::try_from(session.len())
            .map_err(|_| JsError::new("plan produces too many steps for u32"))?;

        let mut hashes = Vec::new();
        while let Some(step) = session.step().map_err(spend_session_err)? {
            let current = u32::try_from(session.step_index().saturating_add(1))
                .map_err(|_| JsError::new("step index exceeds u32"))?;

            let prepared = self
                .prove_transact_inner(
                    &pool_contract_id,
                    &user_address,
                    membership_blinding,
                    &step,
                    flow,
                    &on_status,
                    Some(current),
                    Some(total_u32),
                )
                .await?;
            let prepared = match prepared {
                None => return Ok(None),
                Some(p) => p,
            };

            emit_progress(
                &on_status,
                flow,
                "submit",
                format!("Submitting step {current}/{total_u32}…"),
                Some(current),
                Some(total_u32),
            );
            let hash = Self::call_js_submit(&submit_fn, &prepared).await?;
            session
                .complete_step(&prepared.prepared.output_commitments)
                .map_err(spend_session_err)?;
            hashes.push(hash);
        }

        Ok(Some(hashes))
    }
}
