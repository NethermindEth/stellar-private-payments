use crate::{AppState, deployment, get_events, jsonrpc, storage};
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
use std::{
    sync::{Arc, atomic::Ordering},
    time::Instant,
};
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
        acme = acme.directory(dir.as_str());
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

    let tip = state.ledger_tip.load(Ordering::Relaxed);
    let kv = match storage::load_kv(&state.db).await {
        Ok(kv) => kv,
        Err(e) => {
            tracing::warn!(error = %e, "healthz: failed to load kv");
            return (StatusCode::SERVICE_UNAVAILABLE, "kv unavailable");
        }
    };

    // Consider unhealthy if we haven't indexed within a full redirect window.
    let cutoff = state.cfg.cutoff_ledgers();
    if tip > 0 && kv.last_fully_indexed_ledger.saturating_add(cutoff) < tip {
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
    histogram!("bootnode_request_body_bytes").record(
        u32::try_from(bytes.len())
            .map(f64::from)
            .unwrap_or(f64::from(u32::MAX)),
    );
    if content_len > 0 {
        histogram!("bootnode_request_content_length_bytes").record(
            u32::try_from(content_len)
                .map(f64::from)
                .unwrap_or(f64::from(u32::MAX)),
        );
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

async fn handle_get_latest_ledger(
    state: &AppState,
    id: serde_json::Value,
) -> anyhow::Result<Response> {
    let result = state.upstream.get_latest_ledger().await?;
    Ok(json_response(StatusCode::OK, &jsonrpc::ok(id, result)))
}

async fn handle_get_events(
    state: &AppState,
    id: serde_json::Value,
    params: &serde_json::Value,
) -> anyhow::Result<Response> {
    let deployment = deployment::deployment_config()?;
    let allowed_ids = stellar::contract_ids_for_indexer(&deployment);

    let parsed = match get_events::parse_get_events_params(params) {
        Ok(v) => v,
        Err(_) => {
            return Ok(json_response(
                StatusCode::OK,
                &jsonrpc::invalid_params(id, "invalid getEvents params"),
            ));
        }
    };
    if !get_events::is_allowed_filters(params, &allowed_ids) {
        return Ok(json_response(
            StatusCode::OK,
            &jsonrpc::invalid_params(id, "unsupported filters"),
        ));
    }

    let tip = state.ledger_tip.load(Ordering::Relaxed);
    let cutoff_ledger = tip.saturating_sub(state.cfg.cutoff_ledgers());

    let effective = match (parsed.start_ledger, parsed.cursor.as_deref()) {
        (Some(start_ledger), None) => Some(start_ledger),
        (None, Some(cursor)) => storage::lookup_cursor_ledger(&state.db, cursor).await?,
        _ => None,
    };

    if let Some(effective) = effective
        && effective >= cutoff_ledger
    {
        counter!("bootnode_redirects_total").increment(1);
        return Ok(redirect_307(state.cfg.upstream_rpc_url.as_str()));
    }

    // Serve from cache.
    let cached = match (parsed.start_ledger, parsed.cursor) {
        (Some(start_ledger), None) => {
            storage::get_cached_get_events_by_start_ledger(&state.db, start_ledger).await?
        }
        (None, Some(cursor)) => {
            storage::get_cached_get_events_by_cursor(&state.db, &cursor).await?
        }
        _ => None,
    };

    let Some(result) = cached else {
        counter!("bootnode_cache_misses_total").increment(1);
        let mut resp = json_response(
            StatusCode::OK,
            &jsonrpc::cache_miss(id, "cache miss; indexer may still be catching up"),
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
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
    histogram!("bootnode_response_body_bytes").record(
        u32::try_from(body.len())
            .map(f64::from)
            .unwrap_or(f64::from(u32::MAX)),
    );

    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}
