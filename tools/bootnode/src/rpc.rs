use crate::AppState;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::{ErrorObject, error::ErrorObjectOwned},
};
use metrics::counter;
use serde_json::json;
use std::sync::atomic::Ordering;
use stellar::{
    ContractEventFilter, GetEventsParams, GetEventsResponse, GetLatestLedgerResponse,
    PaginationParams,
};

pub const CACHE_MISS_CODE: i32 = -32_004;
pub const RETENTION_HANDOFF_CODE: i32 = -32_005;

#[rpc(server)]
pub trait BootnodeApi {
    #[method(name = "getLatestLedger")]
    async fn get_latest_ledger(&self) -> RpcResult<GetLatestLedgerResponse>;

    #[method(name = "getEvents", param_kind = map)]
    async fn get_events(
        &self,
        filters: Vec<ContractEventFilter>,
        pagination: PaginationParams,
        #[argument(rename = "startLedger")] start_ledger: Option<u32>,
        #[argument(rename = "endLedger")] end_ledger: Option<u32>,
        #[argument(rename = "xdrFormat")] xdr_format: Option<String>,
    ) -> RpcResult<GetEventsResponse>;
}

pub struct BootnodeRpc {
    state: AppState,
}

impl BootnodeRpc {
    // getEvents request flow
    //                    getEvents request
    //                           │
    //           ┌───────────────┴───────────────┐
    //           │                               │
    //    startLedger only                  cursor only
    //           │                               │
    //    tip known & ledger              tip known & cursor's
    //    >= cutoff? ──yes──► -32005       last event ledger
    //    handoff          handoff              >= cutoff?
    //           │no                             │yes
    //           ▼                               ▼
    //    cache by startLedger              -32005 handoff
    //           │                               │no
    //    ┌──────┴──────┐                        ▼
    //   hit           miss              cache by cursor
    //    │             │                        │
    //    ▼             ▼                  ┌─────┴─────┐
    //  200 OK     -32004 miss            hit         miss
    //             (warming up             │           │
    //              if tip==0)             ▼           ▼
    //                                   200 OK     -32004 miss
    async fn get_events_handler(&self, params: &GetEventsParams) -> RpcResult<GetEventsResponse> {
        let parsed = params.parsed().map_err(|e| invalid_params(e.to_string()))?;
        if !params.is_allowed_filters(self.state.contract_ids.as_ref()) {
            return Err(invalid_params("unsupported filters"));
        }

        let tip = self.state.ledger_tip.load(Ordering::Relaxed);
        let tip_known = tip > 0;
        let cutoff_ledger = tip.saturating_sub(self.state.cfg.cutoff_ledgers());

        let handoff_ledger = match (parsed.start_ledger, parsed.cursor.as_deref()) {
            (Some(start_ledger), None) => Some(start_ledger),
            (None, Some(cursor)) => {
                let last_event_ledger = self
                    .state
                    .storage
                    .lookup_last_event_ledger_for_cursor(cursor)
                    .await
                    .map_err(|e| {
                        counter!("bootnode_handler_errors_total").increment(1);
                        internal_error(e)
                    })?;

                if tip_known
                    && let Some(last_event_ledger) = last_event_ledger
                    && last_event_ledger >= cutoff_ledger
                {
                    counter!("bootnode_handoffs_total").increment(1);
                    return Err(retention_handoff(cutoff_ledger));
                }

                let Some(result) = self
                    .state
                    .storage
                    .get_cached_get_events_by_cursor(cursor)
                    .await
                    .map_err(|e| {
                        counter!("bootnode_handler_errors_total").increment(1);
                        internal_error(e)
                    })?
                else {
                    counter!("bootnode_cache_misses_total").increment(1);
                    return Err(cache_miss_for_tip(tip));
                };

                counter!("bootnode_cache_hits_total").increment(1);
                return Ok(result);
            }
            _ => None,
        };

        if tip_known
            && let Some(handoff_ledger) = handoff_ledger
            && handoff_ledger >= cutoff_ledger
        {
            counter!("bootnode_handoffs_total").increment(1);
            return Err(retention_handoff(cutoff_ledger));
        }

        let cached = match parsed.start_ledger {
            Some(start_ledger) => {
                self.state
                    .storage
                    .get_cached_get_events_by_start_ledger(start_ledger)
                    .await
            }
            None => Ok(None),
        }
        .map_err(|e| {
            counter!("bootnode_handler_errors_total").increment(1);
            internal_error(e)
        })?;

        let Some(result) = cached else {
            counter!("bootnode_cache_misses_total").increment(1);
            return Err(cache_miss_for_tip(tip));
        };

        counter!("bootnode_cache_hits_total").increment(1);
        Ok(result)
    }
}

#[async_trait]
impl BootnodeApiServer for BootnodeRpc {
    async fn get_latest_ledger(&self) -> RpcResult<GetLatestLedgerResponse> {
        self.state.upstream.get_latest_ledger().await.map_err(|e| {
            counter!("bootnode_handler_errors_total").increment(1);
            internal_error(e)
        })
    }

    async fn get_events(
        &self,
        filters: Vec<ContractEventFilter>,
        pagination: PaginationParams,
        start_ledger: Option<u32>,
        end_ledger: Option<u32>,
        xdr_format: Option<String>,
    ) -> RpcResult<GetEventsResponse> {
        let params = GetEventsParams {
            filters,
            pagination,
            start_ledger,
            end_ledger,
            xdr_format,
        };
        // Bootnode intentionally supports a narrow subset of getEvents.
        if params.end_ledger.is_some() {
            return Err(invalid_params("endLedger is not supported by bootnode"));
        }
        if params.xdr_format.is_some() {
            return Err(invalid_params("xdrFormat is not supported by bootnode"));
        }
        self.get_events_handler(&params).await
    }
}

pub(crate) fn build_rpc_module(state: AppState) -> jsonrpsee::Methods {
    BootnodeRpc { state }.into_rpc().into()
}

fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObject::owned(-32_602, msg.into(), None::<()>)
}

fn internal_error(err: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObject::owned(-32_603, err.to_string(), None::<()>)
}

pub fn cache_miss(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObject::owned(CACHE_MISS_CODE, msg.into(), None::<()>)
}

fn cache_miss_for_tip(tip: u32) -> ErrorObjectOwned {
    if tip == 0 {
        cache_miss("bootnode warming up; retry later")
    } else {
        cache_miss("cache miss; indexer may still be catching up")
    }
}

pub fn retention_handoff(from_ledger: u32) -> ErrorObjectOwned {
    ErrorObject::owned(
        RETENTION_HANDOFF_CODE,
        "Continue syncing on your RPC endpoint",
        Some(json!({
            "reason": "retention_threshold",
            "fromLedger": from_ledger,
        })),
    )
}
