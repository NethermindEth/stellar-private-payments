//! Bootnode library — core service logic and integration-test surface.
#![forbid(unsafe_code)]

pub mod config;
pub mod get_events;
pub mod jsonrpc;
pub mod metrics;
pub mod otel;

mod deployment;
mod http_server;
mod indexer;
mod storage;
mod upstream;

use anyhow::{Context, Result};
use config::Config;
use std::sync::{Arc, atomic::AtomicU32};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct AppState {
    pub(crate) cfg: Arc<Config>,
    pub(crate) db: deadpool_postgres::Pool,
    pub(crate) upstream: upstream::UpstreamClient,
    pub(crate) tip_ledger: Arc<AtomicU32>,
    pub(crate) prom_handle: metrics_exporter_prometheus::PrometheusHandle,
}

pub async fn build_state(
    cfg: Arc<Config>,
    prom_handle: metrics_exporter_prometheus::PrometheusHandle,
) -> Result<AppState> {
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

    Ok(AppState {
        cfg,
        db,
        upstream,
        tip_ledger,
        prom_handle,
    })
}

pub async fn serve(state: AppState) -> Result<()> {
    let mut indexer_task: JoinHandle<()> = tokio::spawn(indexer::run_indexer(state.clone()));
    let mut server_task: JoinHandle<Result<()>> = tokio::spawn(http_server::run_http(state));

    tokio::select! {
        res = &mut server_task => {
            indexer_task.abort();
            res??;
        }
        _ = &mut indexer_task => {
            anyhow::bail!("indexer task exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
        }
    }

    Ok(())
}
