//! Bootnode library — core service logic and integration-test surface.
#![forbid(unsafe_code)]

pub mod config;
pub mod metrics;
pub mod otel;
pub mod rpc;

mod deployment;
mod http_server;
mod indexer;
mod storage;
mod upstream;

use anyhow::{Context, Result};
use config::Config;
use std::sync::{Arc, atomic::AtomicU32};

use self::{indexer::Indexer, upstream::UpstreamClient};

pub struct Bootnode {
    state: AppState,
}

/// Shared runtime state for HTTP handlers and the background indexer.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) cfg: Arc<Config>,
    pub(crate) db: deadpool_postgres::Pool,
    pub(crate) upstream: UpstreamClient,
    pub(crate) ledger_tip: Arc<AtomicU32>,
    pub(crate) prom_handle: metrics_exporter_prometheus::PrometheusHandle,
}

impl Bootnode {
    pub async fn setup(
        cfg: Config,
        prom_handle: metrics_exporter_prometheus::PrometheusHandle,
    ) -> Result<Self> {
        let cfg = Arc::new(cfg);
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

        let ledger_tip = Arc::new(AtomicU32::new(0));
        let upstream = UpstreamClient::new(cfg.upstream_rpc_url.clone())?;

        Ok(Self {
            state: AppState {
                cfg,
                db,
                upstream,
                ledger_tip,
                prom_handle,
            },
        })
    }

    pub async fn serve(self) -> Result<()> {
        let state = self.state;
        let mut indexer_task = tokio::spawn(Indexer::new(state.clone()).run());
        let mut server_task = tokio::spawn(http_server::run_http(state));

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
}
