use crate::{AppState, rpc, storage};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use http_body_util::BodyExt;
use jsonrpsee::server::{BatchRequestConfig, Server, ServerConfig, TowerService, stop_channel};
use metrics::{gauge, histogram};
use std::{sync::Arc, time::Instant};
use tower::Service;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{
    cors::{Any, CorsLayer},
    set_header::SetResponseHeaderLayer,
    trace::TraceLayer,
};

type RpcService = TowerService<tower::layer::util::Identity, tower::layer::util::Identity>;

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

    let (stop_handle, _server_handle) = stop_channel();
    let methods = rpc::build_rpc_module(state.clone());
    let server_cfg = ServerConfig::builder()
        .http_only()
        .max_request_body_size(1024 * 1024)
        .set_batch_request_config(BatchRequestConfig::Disabled)
        .build();
    let rpc_svc = Arc::new(
        Server::builder()
            .set_config(server_cfg)
            .to_service_builder()
            .build(methods, stop_handle),
    );

    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/", post(handle_rpc))
        .with_state(RpcState {
            app: state.clone(),
            rpc: rpc_svc,
        })
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

#[derive(Clone)]
struct RpcState {
    app: AppState,
    rpc: Arc<RpcService>,
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

async fn metrics(State(state): State<RpcState>) -> impl IntoResponse {
    state.app.prom_handle.render()
}

async fn healthz(State(state): State<RpcState>) -> impl IntoResponse {
    use std::sync::atomic::Ordering;

    match state.app.db.get().await {
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

    let tip = state.app.ledger_tip.load(Ordering::Relaxed);
    let kv = match storage::load_kv(&state.app.db).await {
        Ok(kv) => kv,
        Err(e) => {
            tracing::warn!(error = %e, "healthz: failed to load kv");
            return (StatusCode::SERVICE_UNAVAILABLE, "kv unavailable");
        }
    };

    // Unhealthy if the indexer is more than one handoff window behind tip.
    let cutoff = state.app.cfg.cutoff_ledgers();
    if tip > 0 && kv.last_fully_indexed_ledger.saturating_add(cutoff) < tip {
        return (StatusCode::SERVICE_UNAVAILABLE, "indexer behind");
    }

    (StatusCode::OK, "ok")
}

async fn handle_rpc(State(state): State<RpcState>, req: Request<Body>) -> Response {
    let t0 = Instant::now();
    let content_len = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    gauge!("bootnode_inflight_requests").increment(1.0);

    let mut rpc = state.rpc.as_ref().clone();
    let result = rpc.call(req).await;

    gauge!("bootnode_inflight_requests").decrement(1.0);
    histogram!("bootnode_request_duration_seconds").record(t0.elapsed().as_secs_f64());
    if content_len > 0 {
        let bytes = u32::try_from(content_len)
            .map(f64::from)
            .unwrap_or(f64::from(u32::MAX));
        histogram!("bootnode_request_body_bytes").record(bytes);
        histogram!("bootnode_request_content_length_bytes").record(bytes);
    }

    match result {
        Ok(response) => {
            let (parts, body) = response.into_parts();
            match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    histogram!("bootnode_response_body_bytes").record(
                        u32::try_from(bytes.len())
                            .map(f64::from)
                            .unwrap_or(f64::from(u32::MAX)),
                    );
                    Response::from_parts(parts, Body::from(bytes))
                }
                Err(err) => {
                    tracing::warn!(error = %err, "failed to read rpc response body for metrics");
                    Response::from_parts(parts, Body::empty())
                }
            }
        }
        Err(err) => {
            tracing::error!(error = %err, "json-rpc service error");
            (StatusCode::INTERNAL_SERVER_ERROR, "json-rpc service error").into_response()
        }
    }
}
