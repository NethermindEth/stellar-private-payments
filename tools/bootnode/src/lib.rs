//! Bootnode library — core service logic and integration-test surface.
#![forbid(unsafe_code)]

pub mod config;
pub mod messages;
pub mod metrics;
pub mod otel;
pub mod rpc;
pub mod storage;

mod deployment;
mod http_server;
mod indexer;
mod upstream;

use anyhow::Result;
use config::Config;
use std::sync::{Arc, atomic::AtomicU32};
use storage::Storage;

use self::{http_server::HttpServer, indexer::Indexer, upstream::UpstreamClient};

pub use storage::{InMemory, Postgres};

pub struct Bootnode {
    state: AppState,
}

/// Shared runtime state for HTTP handlers and the background indexer.
#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) cfg: Arc<Config>,
    pub(crate) storage: Arc<dyn Storage>,
    pub(crate) upstream: UpstreamClient,
    pub(crate) ledger_tip: Arc<AtomicU32>,
    pub(crate) prom_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub(crate) contract_ids: Arc<Vec<String>>,
    pub(crate) min_deployment_ledger: u32,
}

impl Bootnode {
    pub async fn setup(
        cfg: Config,
        storage: Arc<dyn Storage>,
        prom_handle: metrics_exporter_prometheus::PrometheusHandle,
    ) -> Result<Self> {
        let cfg = Arc::new(cfg);
        let deployment = deployment::deployment_config()?;
        let contract_ids = Arc::new(deployment.pools_and_membership_contract_ids());
        let min_deployment_ledger = deployment.min_deployment_ledger()?;
        let kv = storage.load_kv().await?;
        let ledger_tip = cfg.initial_ledger_tip.max(kv.ledger_tip);

        Ok(Self {
            state: AppState {
                upstream: UpstreamClient::new(cfg.upstream_rpc_url.clone())?,
                ledger_tip: Arc::new(AtomicU32::new(ledger_tip)),
                cfg,
                storage,
                prom_handle,
                contract_ids,
                min_deployment_ledger,
            },
        })
    }

    pub async fn serve(self) -> Result<()> {
        let state = self.state;
        let mut indexer_task = tokio::spawn(Indexer::new(state.clone()).run());
        let mut server_task = tokio::spawn(HttpServer::new(state).run());

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
