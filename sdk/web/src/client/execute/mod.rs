//! Prove / simulate / sign / submit loop with transaction progress events.

mod progress;

use gloo_timers::future::TimeoutFuture;
use stellar_private_payments::{
    Error,
    plan::PreparedTransactionPlan,
    types::{AspMembershipSync, TransactionResult},
};
use wasm_bindgen::JsError;

use crate::models::{ExecuteOutcome, PoolExecuteResult};

use super::pool::PrivatePool;

pub(crate) use progress::emit;

const POLL_INTERVAL_MS: u32 = 200;
const SYNC_MAX_RETRIES: u32 = 50;

impl PrivatePool {
    pub(crate) async fn execute_plan(
        &self,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
    ) -> Result<PoolExecuteResult, JsError> {
        let outcome = self.execute_plan_inner(plan, flow).await;
        Ok(PoolExecuteResult::from_outcome(outcome))
    }

    async fn execute_plan_inner(
        &self,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
    ) -> ExecuteOutcome {
        let pool = self.inner();
        let total = plan.tx_count();
        let mut completed = Vec::new();

        while !plan.is_complete() {
            let current = plan.current_tx().saturating_add(1);
            let mut sync_waits = 0u32;

            let mut prepared = loop {
                progress::emit(
                    flow,
                    "prove",
                    step_msg("Proving", current, total),
                    Some(current),
                    Some(total),
                );

                match pool.prove_next(plan).await {
                    Ok(prepared) => break prepared,
                    Err(error @ Error::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                        if completed.is_empty() {
                            return ExecuteOutcome::AspNotReady;
                        }
                        return ExecuteOutcome::plan(completed, error);
                    }
                    Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                        sync_waits = sync_waits.saturating_add(1);
                        if sync_waits > SYNC_MAX_RETRIES {
                            return ExecuteOutcome::plan(
                                completed,
                                Error::MembershipSync(AspMembershipSync::SyncRequired(gap)),
                            );
                        }
                        progress::emit(
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
                        TimeoutFuture::new(POLL_INTERVAL_MS).await;
                    }
                    Err(error) => return ExecuteOutcome::plan(completed, error),
                }
            };

            progress::emit(
                flow,
                "simulate",
                step_msg("Simulating", current, total),
                Some(current),
                Some(total),
            );
            if let Err(error) = pool.simulate(&mut prepared).await {
                return ExecuteOutcome::plan(completed, error);
            }

            progress::emit(
                flow,
                "sign",
                step_msg("Signing", current, total),
                Some(current),
                Some(total),
            );
            let signed = match pool.sign(&prepared).await {
                Ok(signed) => signed,
                Err(error) => return ExecuteOutcome::plan(completed, error),
            };

            progress::emit(
                flow,
                "submit",
                step_msg("Submitting", current, total),
                Some(current),
                Some(total),
            );
            let hash = match pool.submit(signed).await {
                Ok(hash) => hash,
                Err(error) => return ExecuteOutcome::plan(completed, error),
            };
            if let Err(error) = pool.confirm(&hash).await {
                return ExecuteOutcome::plan(completed, error);
            }
            completed.push(TransactionResult { tx_hash: hash });
        }

        ExecuteOutcome::Complete(completed.into_iter().map(|tx| tx.tx_hash).collect())
    }
}

fn step_msg(verb: &str, current: u32, total: u32) -> String {
    if total > 1 {
        format!("{verb} step {current}/{total}…")
    } else {
        format!("{verb}…")
    }
}
