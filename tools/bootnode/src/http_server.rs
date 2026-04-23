use crate::{AppState, jsonrpc, storage};
use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use metrics::{counter, gauge, histogram};
use serde::Serialize;
use std::{sync::atomic::Ordering, time::Instant};
use std::sync::Arc;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

pub(crate) async fn run_http(state: AppState) -> anyhow::Result<()> {
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(state.cfg.rate_limit_rps.into())
        .burst_size(state.cfg.rate_limit_burst)
        .finish()
        .expect("governor config is valid");

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let router = Router::new()
        .route("/", post(handle_jsonrpc))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(GovernorLayer {
            config: Arc::new(governor_conf),
        })
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        ));

    let router = if state.cfg.insecure_http {
        router
    } else {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
    };

    tracing::info!(bind = %state.cfg.bind, insecure_http = state.cfg.insecure_http, "starting server");

    if state.cfg.insecure_http {
        let listener = tokio::net::TcpListener::bind(state.cfg.bind).await?;
        axum::serve(listener, router).await?;
        return Ok(());
    }

    run_https_acme(state, router).await
}

async fn run_https_acme(state: AppState, router: Router) -> anyhow::Result<()> {
    use rustls_acme::{AcmeConfig, caches::DirCache};

    let domain = state
        .cfg
        .domain
        .clone()
        .ok_or_else(|| anyhow::anyhow!("domain missing"))?;
    let email = state
        .cfg
        .acme_email
        .clone()
        .ok_or_else(|| anyhow::anyhow!("acme email missing"))?;

    let mut acme = AcmeConfig::new([domain])
        .contact_push(format!("mailto:{email}"))
        .cache(DirCache::new(state.cfg.acme_cache_dir.clone()));

    if let Some(dir) = state.cfg.acme_directory_url.clone() {
        acme = acme.directory(dir.to_string());
    }

    let acme_state = acme.state();
    let rustls_config = acme_state.default_rustls_config();
    let acceptor = acme_state.axum_acceptor(rustls_config);

    axum_server::bind(state.cfg.bind)
        .acceptor(acceptor)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    state.prom_handle.render()
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get().await {
        Ok(client) => {
            if let Err(e) = client.query_one("SELECT 1", &[]).await {
                tracing::warn!(error = %e, "healthz: db query failed");
                return (StatusCode::SERVICE_UNAVAILABLE, "db unavailable");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "healthz: db pool unavailable");
            return (StatusCode::SERVICE_UNAVAILABLE, "db unavailable");
        }
    }

    let tip = state.tip_ledger.load(Ordering::Relaxed);
    let kv = match storage::load_kv(&state.db).await {
        Ok(kv) => kv,
        Err(e) => {
            tracing::warn!(error = %e, "healthz: failed to load kv");
            return (StatusCode::SERVICE_UNAVAILABLE, "kv unavailable");
        }
    };

    // Consider unhealthy if we haven't indexed within a full redirect window.
    let cutoff = state.cfg.cutoff_ledgers();
    if tip > 0 && kv.last_fully_indexed_ledger + cutoff < tip {
        return (StatusCode::SERVICE_UNAVAILABLE, "indexer behind");
    }

    (StatusCode::OK, "ok")
}

async fn handle_jsonrpc(
    State(state): State<AppState>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    let t0 = Instant::now();
    let content_len = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    gauge!("bootnode_inflight_requests").increment(1.0);

    let req: jsonrpc::JsonRpcRequest = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            gauge!("bootnode_inflight_requests").decrement(1.0);
            counter!("bootnode_json_parse_errors_total").increment(1);
            let err = jsonrpc::parse_error(format!("invalid jsonrpc request: {e}"));
            return json_response(StatusCode::OK, &err);
        }
    };

    let id = req.id.clone().unwrap_or_else(jsonrpc::null_id);

    let resp = match req.method.as_str() {
        "getLatestLedger" => handle_get_latest_ledger(&state, id.clone()).await,
        "getEvents" => handle_get_events(&state, id.clone(), &req.params).await,
        _ => Ok(json_response(
            StatusCode::OK,
            &jsonrpc::method_not_found(id.clone()),
        )),
    };

    gauge!("bootnode_inflight_requests").decrement(1.0);

    let dt = t0.elapsed().as_secs_f64();
    histogram!("bootnode_request_duration_seconds").record(dt);
    histogram!("bootnode_request_body_bytes").record(bytes.len() as f64);
    if content_len > 0 {
        histogram!("bootnode_request_content_length_bytes").record(content_len as f64);
    }

    match resp {
        Ok(r) => r,
        Err(e) => {
            counter!("bootnode_handler_errors_total").increment(1);
            let err = jsonrpc::internal_error(id, e.to_string());
            json_response(StatusCode::OK, &err)
        }
    }
}

async fn handle_get_latest_ledger(state: &AppState, id: serde_json::Value) -> anyhow::Result<Response> {
    let result = state.upstream.get_latest_ledger().await?;
    Ok(json_response(StatusCode::OK, &jsonrpc::ok(id, result)))
}

async fn handle_get_events(
    state: &AppState,
    id: serde_json::Value,
    params: &serde_json::Value,
) -> anyhow::Result<Response> {
    let deployment = stellar::deployment_config()?;
    let allowed_ids = vec![deployment.pool, deployment.asp_membership];

    let parsed = match parse_get_events_params(params) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_response(
                StatusCode::OK,
                &jsonrpc::invalid_params(id, "invalid getEvents params"),
            ));
        }
    };
    if !is_allowed_filters(params, &allowed_ids) {
        return Ok(json_response(
            StatusCode::OK,
            &jsonrpc::invalid_params(id, "unsupported filters"),
        ));
    }

    let tip = state.tip_ledger.load(Ordering::Relaxed);
    let cutoff_ledger = tip.saturating_sub(state.cfg.cutoff_ledgers());

    let effective = match &parsed {
        ParsedGetEvents::StartLedger { start_ledger, .. } => Some(*start_ledger),
        ParsedGetEvents::Cursor { cursor, .. } => {
            storage::lookup_cursor_ledger(&state.db, cursor).await?
        }
    };

    if let Some(effective) = effective
        && effective >= cutoff_ledger
    {
        counter!("bootnode_redirects_total").increment(1);
        return Ok(redirect_307(state.cfg.upstream_rpc_url.as_str()));
    }

    // Serve from cache.
    let cached = match parsed {
        ParsedGetEvents::StartLedger { start_ledger, .. } => {
            storage::get_cached_get_events_by_start_ledger(&state.db, start_ledger).await?
        }
        ParsedGetEvents::Cursor { cursor, .. } => {
            storage::get_cached_get_events_by_cursor(&state.db, &cursor).await?
        }
    };

    let Some(result) = cached else {
        counter!("bootnode_cache_misses_total").increment(1);
        let mut resp = json_response(
            StatusCode::OK,
            &jsonrpc::cache_miss(id, "cache miss; indexer may still be catching up"),
        );
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        return Ok(resp);
    };

    counter!("bootnode_cache_hits_total").increment(1);
    Ok(json_response(StatusCode::OK, &jsonrpc::ok(id, result)))
}

fn redirect_307(location: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    let body = match serde_json::to_vec(value) {
        Ok(v) => v,
        Err(_) => b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"serialization failed\"}}".to_vec(),
    };
    histogram!("bootnode_response_body_bytes").record(body.len() as f64);

    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

#[derive(Debug, Clone)]
enum ParsedGetEvents {
    StartLedger { start_ledger: u32, limit: Option<u32> },
    Cursor { cursor: String, limit: Option<u32> },
}

fn parse_get_events_params(params: &serde_json::Value) -> anyhow::Result<ParsedGetEvents> {
    let start_ledger = params.get("startLedger").and_then(|v| v.as_u64()).map(|v| v as u32);
    let pagination = params.get("pagination").and_then(|v| v.as_object());
    let limit = pagination
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let cursor = pagination
        .and_then(|p| p.get("cursor"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    match (start_ledger, cursor) {
        (Some(start_ledger), None) => Ok(ParsedGetEvents::StartLedger { start_ledger, limit }),
        (None, Some(cursor)) => Ok(ParsedGetEvents::Cursor { cursor, limit }),
        _ => anyhow::bail!("getEvents params must include either startLedger or pagination.cursor"),
    }
}

fn is_allowed_filters(params: &serde_json::Value, allowed_contract_ids: &[String]) -> bool {
    let filters = params.get("filters").and_then(|v| v.as_array());
    let Some(filters) = filters else { return false };
    let Some(first) = filters.first().and_then(|v| v.as_object()) else { return false };

    if let Some(t) = first.get("type").and_then(|v| v.as_str()) {
        if t != "contract" {
            return false;
        }
    } else {
        return false;
    }

    let topics = first.get("topics");
    if topics != Some(&serde_json::json!([[ "**" ]])) {
        return false;
    }

    let contract_ids = first.get("contractIds").and_then(|v| v.as_array());
    let Some(contract_ids) = contract_ids else { return false };
    let mut got: Vec<&str> = contract_ids.iter().filter_map(|v| v.as_str()).collect();
    got.sort_unstable();
    let mut want: Vec<&str> = allowed_contract_ids.iter().map(|s| s.as_str()).collect();
    want.sort_unstable();
    got == want
}
