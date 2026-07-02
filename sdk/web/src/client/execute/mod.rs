//! Prove / simulate / sign / submit loop with transaction progress events.

mod progress;

use gloo_timers::future::TimeoutFuture;
use serde::Serialize;
use stellar_private_payments_sdk::{PoolError, PreparedTransactionPlan, types::AspMembershipSync};
use wasm_bindgen::{JsError, JsValue};

use super::{pool::PrivatePool, pool_err_message};

pub(crate) use progress::emit;

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
    },
    AspNotReady,
}

impl TryInto<JsValue> for ExecuteJsResponse {
    type Error = JsError;

    fn try_into(self) -> Result<JsValue, Self::Error> {
        Ok(serde_wasm_bindgen::to_value(&self)?)
    }
}

impl PrivatePool {
    pub(crate) async fn execute_plan(
        &self,
        plan: &mut PreparedTransactionPlan,
        flow: &'static str,
    ) -> Result<JsValue, JsError> {
        let pool = self.inner();
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
                progress::emit(flow, "prove", prove_message, Some(current), Some(total));

                match pool.prove_next(plan).await {
                    Ok(prepared) => break prepared,
                    Err(error @ PoolError::MembershipSync(AspMembershipSync::RegisterAtASP)) => {
                        if hashes.is_empty() {
                            return ExecuteJsResponse::AspNotReady.try_into();
                        }
                        return ExecuteJsResponse::Failed {
                            hashes,
                            message: pool_err_message(error),
                        }
                        .try_into();
                    }
                    Err(PoolError::MembershipSync(AspMembershipSync::SyncRequired(gap))) => {
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
                        TimeoutFuture::new(1_000).await;
                    }
                    Err(error) => {
                        return ExecuteJsResponse::Failed {
                            hashes,
                            message: pool_err_message(error),
                        }
                        .try_into();
                    }
                }
            };

            let simulate_message = if total > 1 {
                format!("Simulating step {current}/{total}…")
            } else {
                "Simulating…".to_string()
            };
            progress::emit(
                flow,
                "simulate",
                simulate_message,
                Some(current),
                Some(total),
            );
            if let Err(error) = pool.simulate(&mut prepared).await {
                return ExecuteJsResponse::Failed {
                    hashes,
                    message: pool_err_message(error),
                }
                .try_into();
            }

            let sign_message = if total > 1 {
                format!("Signing step {current}/{total}…")
            } else {
                "Signing…".to_string()
            };
            progress::emit(flow, "sign", sign_message, Some(current), Some(total));
            let signed = match pool.sign(&prepared).await {
                Ok(signed) => signed,
                Err(error) => {
                    return ExecuteJsResponse::Failed {
                        hashes,
                        message: pool_err_message(error),
                    }
                    .try_into();
                }
            };

            let submit_message = if total > 1 {
                format!("Submitting step {current}/{total}…")
            } else {
                "Submitting…".to_string()
            };
            progress::emit(flow, "submit", submit_message, Some(current), Some(total));
            let hash = match pool.submit(signed).await {
                Ok(hash) => hash,
                Err(error) => {
                    return ExecuteJsResponse::Failed {
                        hashes,
                        message: pool_err_message(error),
                    }
                    .try_into();
                }
            };
            if let Err(error) = pool.confirm(&hash).await {
                return ExecuteJsResponse::Failed {
                    hashes,
                    message: pool_err_message(error),
                }
                .try_into();
            }
            hashes.push(hash);
        }

        ExecuteJsResponse::Complete { hashes }.try_into()
    }
}
