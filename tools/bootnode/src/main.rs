//! Bootnode service that caches a minimal subset of Stellar JSON-RPC calls
//! (`getEvents`, `getLatestLedger`) for the PoolStellar indexer.
//!
//! The server is intended to bridge RPC retention windows by serving historical
//! `getEvents` pages from a Postgres cache, and safely redirecting clients back
//! to an upstream RPC once their requested cursor/start ledger is within the
//! retention window buffer.
#![forbid(unsafe_code)]

mod config;
mod http_server;
mod indexer;
mod jsonrpc;
mod metrics;
mod otel;
mod storage;
mod upstream;

use anyhow::{Context, Result};
use config::Config;
use std::sync::{Arc, atomic::AtomicU32};
use tokio::task::JoinHandle;

#[derive(Clone)]
struct AppState {
    cfg: Arc<Config>,
    db: deadpool_postgres::Pool,
    upstream: upstream::UpstreamClient,
    tip_ledger: Arc<AtomicU32>,
    prom_handle: metrics_exporter_prometheus::PrometheusHandle,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Arc::new(Config::parse_and_validate()?);

    let _otel_guard = otel::init_telemetry(&cfg)?;
    metrics::init_metrics()?;

    let prom_handle = metrics::install_prometheus_recorder()?;

    let pg_cfg: tokio_postgres::Config = cfg
        .database_url
        .parse()
        .context("failed to parse DATABASE_URL")?;
    let mgr = deadpool_postgres::Manager::new(pg_cfg, tokio_postgres::NoTls);
    let db = deadpool_postgres::Pool::builder(mgr)
        .max_size(cfg.db_max_connections as usize)
        .build()
        .expect("pool build cannot fail");

    storage::init_db(&db).await?;

    let tip_ledger = Arc::new(AtomicU32::new(0));
    let upstream = upstream::UpstreamClient::new(cfg.upstream_rpc_url.clone())?;

    let state = AppState {
        cfg: cfg.clone(),
        db: db.clone(),
        upstream: upstream.clone(),
        tip_ledger: tip_ledger.clone(),
        prom_handle,
    };

    let mut indexer_task: JoinHandle<()> = tokio::spawn(indexer::run_indexer(state.clone()));
    let mut server_task: JoinHandle<Result<()>> = tokio::spawn(http_server::run_http(state));

    tokio::select! {
        res = &mut server_task => {
            indexer_task.abort();
            res??;
        }
        _ = &mut indexer_task => {
            // Indexer is designed to be resilient and should not exit.
            // If it does, stop the server to avoid serving stale data.
            anyhow::bail!("indexer task exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    Ok(())
}
