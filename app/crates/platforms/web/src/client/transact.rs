//! Pool transaction proving and execution (`executeDeposit`, `executeTransact`,
//! `executeTransfer`, `executeWithdraw`).

use super::{
    WebClient, emit_progress, parse_ext_amount_decimal, parse_input_note_ids,
    parse_note_amount_decimal, parse_output_amounts, parse_output_recipient_keys,
    parse_u32_decimal, sign::sign_prepared_transaction,
};
use crate::protocol::{
    PreparedProverTx, ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest,
    StorageWorkerResponse, TransactRequest,
};
use gloo_timers::future::TimeoutFuture;
use js_sys::{Array, BigInt, Function};
use prover::flows::N_OUTPUTS;
use serde::Serialize;
use tx_planner::{SpendSession, SpendSessionError, SpendTarget, SpendableNote, Transact, plan};
use types::{
    AspMembershipSync, ContractsStateData, EncryptionPublicKey, ExtAmount, Field, NoteAmount,
    NotePublicKey, SMT_DEPTH,
};
use wasm_bindgen::JsError;

struct ExecuteCtx {
    pool_contract_id: String,
    user_address: String,
    network_passphrase: String,
    on_status: Option<Function>,
}

struct ExecutedTransact {
    hash: String,
    output_commitments: [Field; 2],
}

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

    pub(super) async fn prove_transact_inner(
        &self,
        pool_contract_id: &str,
        user_address: &str,
        step: &Transact,
        flow: &'static str,
        on_status: &Option<Function>,
    ) -> Result<Option<PreparedProverTx>, JsError> {
        emit_progress(
            on_status,
            flow,
            "sync_check",
            "Checking sync & ASP membership…",
        );

        let params = loop {
            emit_progress(
                on_status,
                flow,
                "fetch_chain_state",
                "Fetching on-chain state…",
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

            emit_progress(on_status, flow, "load_state", "Loading local keys…");
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

            emit_progress(on_status, flow, "load_state", "Building witness inputs…");
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

        emit_progress(on_status, flow, "prove", "Proving…");
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

        let prepared = self
            .finalize_prepared_prover_tx(pool_contract_id, user_address, prepared, on_status, flow)
            .await?;
        Ok(Some(prepared))
    }

    async fn execute_transact(
        &self,
        ctx: ExecuteCtx,
        step: Transact,
        flow: &'static str,
    ) -> Result<Option<Vec<String>>, JsError> {
        let Some(executed) = self.prove_and_submit(&ctx, &step, flow).await? else {
            return Ok(None);
        };
        Ok(Some(vec![executed.hash]))
    }

    async fn execute_plan(
        &self,
        ctx: ExecuteCtx,
        amount: NoteAmount,
        target: SpendTarget,
        flow: &'static str,
    ) -> Result<Option<Vec<String>>, JsError> {
        let wallet = self
            .load_spendable_wallet(&ctx.pool_contract_id, &ctx.user_address)
            .await?;
        let mut session = SpendSession::setup(wallet, amount, ctx.pool_contract_id.clone(), target)
            .map_err(spend_session_err)?;

        let mut hashes = Vec::new();
        while let Some(step) = session.step().map_err(spend_session_err)? {
            let Some(executed) = self.prove_and_submit(&ctx, &step, flow).await? else {
                return Ok(None);
            };
            session
                .complete_step(&executed.output_commitments)
                .map_err(spend_session_err)?;
            hashes.push(executed.hash);
        }

        Ok(Some(hashes))
    }

    async fn prove_and_submit(
        &self,
        ctx: &ExecuteCtx,
        step: &Transact,
        flow: &'static str,
    ) -> Result<Option<ExecutedTransact>, JsError> {
        let prepared = self
            .prove_transact_inner(
                &ctx.pool_contract_id,
                &ctx.user_address,
                step,
                flow,
                &ctx.on_status,
            )
            .await?;
        let Some(prepared) = prepared else {
            return Ok(None);
        };

        let signed_tx = sign_prepared_transaction(
            &prepared.soroban_tx,
            &ctx.network_passphrase,
            &ctx.user_address,
            flow,
            &ctx.on_status,
        )
        .await?;
        emit_progress(&ctx.on_status, flow, "submit", "Submitting…");
        let hash = self.submit_tx(&signed_tx, flow, &ctx.on_status).await?;
        Ok(Some(ExecutedTransact {
            hash,
            output_commitments: prepared.prepared.output_commitments,
        }))
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

        let ctx = ExecuteCtx {
            pool_contract_id,
            user_address,
            network_passphrase,
            on_status,
        };
        self.execute_transact(ctx, step, flow).await
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
        let out_amounts = parse_output_amounts(&output_amounts)?;

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

        let ctx = ExecuteCtx {
            pool_contract_id,
            user_address,
            network_passphrase,
            on_status,
        };
        self.execute_transact(ctx, step, "deposit").await
    }

    pub(super) async fn plan_inner(
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

        let ctx = ExecuteCtx {
            pool_contract_id,
            user_address,
            network_passphrase,
            on_status,
        };
        self.execute_plan(ctx, amount, target, flow).await
    }
}
