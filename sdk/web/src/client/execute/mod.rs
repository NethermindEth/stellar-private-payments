//! Prove / simulate / sign / submit loop with transaction progress events.

mod progress;

use gloo_timers::future::TimeoutFuture;
use serde::Serialize;
use stellar_private_payments::{
    Error, PlanExecutionError,
    plan::PreparedTransactionPlan,
    types::{AspMembershipSync, TransactionResult},
};
use wasm_bindgen::{JsError, JsValue};

use super::{pool::PrivatePool, pool_err_message};

pub(crate) use progress::emit;

const POLL_INTERVAL_MS: u32 = 200;
const SYNC_MAX_RETRIES: u32 = 50;

type ExecuteOutcome = Result<Vec<String>, ExecuteFailure>;

enum ExecuteFailure {
    /// Mid-plan failure; may be [`Error::PlanExecution`] when some txs already
    /// confirmed, otherwise the bare cause.
    Failed(Error),
    AspNotReady,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum ExecuteJsResponse {
    #[serde(rename = "ok")]
    Complete {
        hashes: Vec<String>,
    },
    Failed {
        hashes: Vec<String>,
        message: String,
        /// SEP-0043 error code, present when the failure was a wallet user
        /// rejection (-4). Lets JS callers classify without parsing `message`.
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
    },
    AspNotReady,
}

impl ExecuteFailure {
    fn plan(completed: Vec<TransactionResult>, error: Error) -> ExecuteOutcome {
        Err(Self::Failed(PlanExecutionError::into_error(
            completed, error,
        )))
    }
}

impl From<ExecuteOutcome> for ExecuteJsResponse {
    fn from(outcome: ExecuteOutcome) -> Self {
        match outcome {
            Ok(hashes) => Self::Complete { hashes },
            Err(ExecuteFailure::Failed(error)) => {
                let hashes = match &error {
                    Error::PlanExecution(plan) => {
                        plan.completed.iter().map(|tx| tx.tx_hash.clone()).collect()
                    }
                    _ => Vec::new(),
                };
                let code = wallet_rejection_code(&error);
                Self::Failed {
                    hashes,
                    message: pool_err_message(error),
                    code,
                }
            }
            Err(ExecuteFailure::AspNotReady) => Self::AspNotReady,
        }
    }
}

impl TryInto<JsValue> for ExecuteJsResponse {
    type Error = JsError;

    fn try_into(self) -> Result<JsValue, Self::Error> {
        Ok(serde_wasm_bindgen::to_value(&self)?)
    }
}

fn step_msg(verb: &str, current: u32, total: u32) -> String {
    if total > 1 {
        format!("{verb} step {current}/{total}…")
    } else {
        format!("{verb}…")
    }
}

/// SEP-0043 error code when the failure cause is a wallet user rejection,
/// unwrapping [`Error::PlanExecution`] to reach the underlying cause.
fn wallet_rejection_code(error: &Error) -> Option<i32> {
    let cause = match error {
        Error::PlanExecution(plan) => plan.cause(),
        other => other,
    };
    match cause {
        Error::UserRejected(_) => Some(-4),
        _ => None,
    }
}

impl PrivatePool {
    pub(crate) async fn execute_plan(
        &self,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
    ) -> Result<JsValue, JsError> {
        let outcome = self.execute_plan_inner(plan, flow).await;
        ExecuteJsResponse::from(outcome).try_into()
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
                            return Err(ExecuteFailure::AspNotReady);
                        }
                        return ExecuteFailure::plan(completed, error);
                    }
                    Err(Error::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
                        sync_waits = sync_waits.saturating_add(1);
                        if sync_waits > SYNC_MAX_RETRIES {
                            return ExecuteFailure::plan(
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
                    Err(error) => return ExecuteFailure::plan(completed, error),
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
                return ExecuteFailure::plan(completed, error);
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
                Err(error) => return ExecuteFailure::plan(completed, error),
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
                Err(error) => return ExecuteFailure::plan(completed, error),
            };
            if let Err(error) = pool.confirm(&hash).await {
                return ExecuteFailure::plan(completed, error);
            }
            completed.push(TransactionResult { tx_hash: hash });
        }

        Ok(completed.into_iter().map(|tx| tx.tx_hash).collect())
    }
}

/// Tests for the SEP-0043 rejection-code mapping exposed to JS.
#[cfg(all(test, target_arch = "wasm32"))]
mod spike_tests {
    // Tests favour `unwrap()` for brevity; the workspace-wide `unwrap_used` deny
    // is meant for production paths, not assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn spike_error_mapping_rejection_code() {
        assert_eq!(
            wallet_rejection_code(&Error::UserRejected("stub halt".to_string())),
            Some(-4),
            "a user rejection must surface as SEP-0043 code -4"
        );

        assert_eq!(
            wallet_rejection_code(&Error::Other("simulate failed".to_string())),
            None,
            "an unrelated failure must not carry a code"
        );

        let mid_plan = PlanExecutionError::into_error(
            vec![TransactionResult {
                tx_hash: "abc123".to_string(),
            }],
            Error::UserRejected("stub halt".to_string()),
        );
        assert_eq!(
            wallet_rejection_code(&mid_plan),
            Some(-4),
            "PlanExecution must be unwrapped to reach the rejection cause"
        );

        let mid_plan_other =
            PlanExecutionError::into_error(Vec::new(), Error::Other("simulate failed".to_string()));
        assert_eq!(wallet_rejection_code(&mid_plan_other), None);
    }
}
