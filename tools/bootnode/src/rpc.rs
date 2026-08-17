use crate::{
    AppState,
    messages::{
        ContractEventFilter, GetEventsParams, GetEventsResponse, GetLatestLedgerResponse,
        PaginationParams,
    },
    storage::{build_response, page_limit, parse_genesis_cursor},
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
    types::{ErrorObject, error::ErrorObjectOwned},
};
use metrics::counter;
use serde_json::json;
use std::sync::atomic::Ordering;

/// `-32004`: bootnode warming up (unknown tip or pre-cutoff archive not ready).
pub const WARMING_UP_CODE: i32 = -32_004;

/// `-32002`: resume `getEvents` on the wallet RPC from `fromLedger`.
pub const RETENTION_HANDOFF_CODE: i32 = -32_002;

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
    /// Main events provider
    ///
    /// Respond with handoff (code -32002) if:
    /// - requested startLedger >= cutoff ledger, or
    /// - requested cursor's ledger >= cutoff ledger.
    ///
    /// Cutoff ledger is 5 days ago from current time.
    ///
    /// Return warm-up (code -32004) while tip is unknown or the pre-cutoff
    /// archive is not ready.
    async fn get_events_handler(&self, params: &GetEventsParams) -> RpcResult<GetEventsResponse> {
        let parsed = params.parsed().map_err(|e| invalid_params(e.to_string()))?;
        if !params.is_allowed_filters(self.state.contract_ids.as_ref()) {
            return Err(invalid_params("unsupported filters"));
        }

        let tip = self.state.ledger_tip.load(Ordering::Relaxed);
        if tip == 0 || !self.state.archive_ready.load(Ordering::Relaxed) {
            counter!("bootnode_warming_up_total").increment(1);
            return Err(warming_up());
        }

        let cutoff_ledger = tip.saturating_sub(self.state.cfg.cutoff_ledgers());
        let limit = page_limit(parsed.limit);

        if parsed
            .start_ledger
            .is_some_and(|start_ledger| start_ledger >= cutoff_ledger)
        {
            counter!("bootnode_handoffs_total").increment(1);
            return Err(retention_handoff(cutoff_ledger));
        }

        let stored_oldest = self.state.oldest_ledger.load(Ordering::Relaxed);
        let oldest_ledger = if stored_oldest > 0 {
            stored_oldest
        } else {
            self.state.min_deployment_ledger
        };

        let events = if let Some(cursor) = parsed.cursor.as_deref() {
            if parse_genesis_cursor(cursor).is_some() {
                counter!("bootnode_handoffs_total").increment(1);
                return Err(retention_handoff(cutoff_ledger));
            }

            let (cursor_ledger, events) = self
                .state
                .storage
                .page_events_cursor(cursor, cutoff_ledger, limit)
                .await
                .map_err(internal_error)?;

            let Some(cursor_ledger) = cursor_ledger else {
                return Err(invalid_params("invalid cursor"));
            };
            if cursor_ledger >= cutoff_ledger {
                counter!("bootnode_handoffs_total").increment(1);
                return Err(retention_handoff(cutoff_ledger));
            }
            if events.is_empty() {
                counter!("bootnode_handoffs_total").increment(1);
                return Err(retention_handoff(cutoff_ledger));
            }

            counter!("bootnode_cache_hits_total").increment(1);
            return Ok(build_response(
                events,
                None,
                parsed.cursor.as_deref(),
                tip,
                oldest_ledger,
            ));
        } else {
            let start_ledger = parsed
                .start_ledger
                .unwrap_or(self.state.min_deployment_ledger);
            self.state
                .storage
                .page_events_ledger(start_ledger, cutoff_ledger, limit)
                .await
                .map_err(internal_error)?
        };

        if events.is_empty() {
            counter!("bootnode_empty_pages_total").increment(1);
            return Ok(build_response(
                events,
                parsed.start_ledger,
                parsed.cursor.as_deref(),
                tip,
                oldest_ledger,
            ));
        }

        counter!("bootnode_cache_hits_total").increment(1);
        Ok(build_response(
            events,
            None,
            parsed.cursor.as_deref(),
            tip,
            oldest_ledger,
        ))
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

fn warming_up() -> ErrorObjectOwned {
    ErrorObject::owned(
        WARMING_UP_CODE,
        "bootnode warming up; retry later",
        None::<()>,
    )
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
