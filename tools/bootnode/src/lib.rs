//! Bootnode library — core service logic and integration-test surface.
#![forbid(unsafe_code)]

pub mod config;
pub mod messages;
pub mod metrics;
pub mod otel;
pub mod rpc;
pub mod storage;

mod compressor;
mod deployment;
mod http_server;
mod indexer;
mod upstream;

use anyhow::Result;
use config::Config;
use std::sync::{Arc, atomic::AtomicU32};
use storage::Storage;

use self::{
    compressor::EmptyPageCompressor, http_server::HttpServer, indexer::Indexer,
    upstream::UpstreamClient,
};

pub use deployment::{current_deployment_storage_id, deployment_storage_id};
pub use storage::{InMemory, Postgres};

/// Contract set + genesis ledger the bootnode indexes and will serve.
#[derive(Debug, Clone)]
pub struct DeploymentSpec {
    pub contract_ids: Vec<String>,
    pub min_deployment_ledger: u32,
}

impl DeploymentSpec {
    pub fn from_compiled() -> Result<Self> {
        let deployment = deployment::deployment_config()?;
        Ok(Self {
            contract_ids: deployment.all_contract_ids(),
            min_deployment_ledger: deployment.min_deployment_ledger()?,
        })
    }
}

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
        Self::setup_with_deployment(cfg, storage, prom_handle, DeploymentSpec::from_compiled()?)
            .await
    }

    pub async fn setup_with_deployment(
        cfg: Config,
        storage: Arc<dyn Storage>,
        prom_handle: metrics_exporter_prometheus::PrometheusHandle,
        deployment: DeploymentSpec,
    ) -> Result<Self> {
        let cfg = Arc::new(cfg);
        let contract_ids = Arc::new(deployment.contract_ids);
        let min_deployment_ledger = deployment.min_deployment_ledger;
        let deployment_id =
            deployment::deployment_storage_id(contract_ids.as_ref(), min_deployment_ledger);
        tracing::info!(
            %deployment_id,
            min_deployment_ledger,
            contracts = contract_ids.len(),
            "bootnode deployment namespace"
        );
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
        let mut compressor_task = tokio::spawn(EmptyPageCompressor::new(state.clone()).run());
        let mut server_task = tokio::spawn(HttpServer::new(state).run());

        tokio::select! {
            res = &mut server_task => {
                indexer_task.abort();
                compressor_task.abort();
                res??;
            }
            _ = &mut indexer_task => {
                compressor_task.abort();
                server_task.abort();
                anyhow::bail!("indexer task exited unexpectedly");
            }
            _ = &mut compressor_task => {
                indexer_task.abort();
                server_task.abort();
                anyhow::bail!("empty page compressor exited unexpectedly");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received ctrl-c, shutting down");
            }
        }

        Ok(())
    }
}
