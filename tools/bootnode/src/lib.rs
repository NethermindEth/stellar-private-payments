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
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU32},
};
use storage::Storage;

use self::{http_server::HttpServer, indexer::Indexer, upstream::UpstreamClient};

pub use deployment::{current_deployment_storage_id, deployment_storage_id, read_deployment};
use stellar_private_payments::types::ContractConfig;
pub use storage::{InMemory, Postgres};

/// Default upstream RPC from the selected deployment.
pub fn default_upstream_rpc_url(deployment: &ContractConfig) -> Result<url::Url> {
    let rpc = deployment
        .rpc_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("deployment config is missing rpcUrl"))?;
    Ok(url::Url::parse(rpc)?)
}

/// Verify the upstream identity before opening or changing deployment storage.
pub async fn validate_upstream_network(url: url::Url, deployment: &ContractConfig) -> Result<()> {
    let passphrase = UpstreamClient::new(url)?.network_passphrase().await?;
    deployment.validate_network(&passphrase)
}

/// Wait for upstream identity to become available before accessing storage.
/// Request failures retry indefinitely; a confirmed mismatch fails immediately.
pub async fn wait_for_upstream_network(url: url::Url, deployment: &ContractConfig) -> Result<()> {
    wait_for_upstream_network_with_backoff(
        url,
        deployment,
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(30),
    )
    .await
}

async fn wait_for_upstream_network_with_backoff(
    url: url::Url,
    deployment: &ContractConfig,
    mut delay: std::time::Duration,
    max_delay: std::time::Duration,
) -> Result<()> {
    // Invalid local configuration cannot be repaired by retrying the RPC.
    deployment.validate_network(deployment.network_passphrase.as_deref().unwrap_or_default())?;
    let upstream = UpstreamClient::new(url)?;
    loop {
        match upstream.network_passphrase().await {
            Ok(passphrase) => return deployment.validate_network(&passphrase),
            Err(error) => {
                tracing::warn!(error = %error, retry_in_seconds = delay.as_secs_f64(),
                    "upstream network check unavailable; waiting before startup");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(max_delay);
            }
        }
    }
}

/// Contract set + genesis ledger the bootnode indexes and will serve.
#[derive(Debug, Clone)]
pub struct DeploymentSpec {
    pub network_passphrase: String,
    pub contract_ids: Vec<String>,
    pub min_deployment_ledger: u32,
}

impl DeploymentSpec {
    pub fn from_config(deployment: &ContractConfig) -> Result<Self> {
        deployment
            .validate_network(deployment.network_passphrase.as_deref().unwrap_or_default())?;
        Ok(Self {
            network_passphrase: deployment.network_passphrase.clone().unwrap_or_default(),
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
    pub(crate) oldest_ledger: Arc<AtomicU32>,
    pub(crate) archive_ready: Arc<AtomicBool>,
    pub(crate) prom_handle: metrics_exporter_prometheus::PrometheusHandle,
    pub(crate) contract_ids: Arc<Vec<String>>,
    pub(crate) min_deployment_ledger: u32,
}

impl Bootnode {
    pub async fn setup_with_deployment(
        cfg: Config,
        storage: Arc<dyn Storage>,
        prom_handle: metrics_exporter_prometheus::PrometheusHandle,
        deployment: DeploymentSpec,
    ) -> Result<Self> {
        let cfg = Arc::new(cfg);
        let contract_ids = Arc::new(deployment.contract_ids);
        let min_deployment_ledger = deployment.min_deployment_ledger;
        let deployment_id = deployment::deployment_storage_id(
            contract_ids.as_ref(),
            min_deployment_ledger,
            &deployment.network_passphrase,
        );
        tracing::info!(
            %deployment_id,
            min_deployment_ledger,
            contracts = contract_ids.len(),
            "bootnode deployment namespace"
        );
        let indexer = storage.load_indexer_state().await?;
        let ledger_tip = cfg.initial_ledger_tip.max(indexer.ledger_tip);

        Ok(Self {
            state: AppState {
                upstream: UpstreamClient::new(cfg.upstream_rpc_url.clone())?,
                ledger_tip: Arc::new(AtomicU32::new(ledger_tip)),
                oldest_ledger: Arc::new(AtomicU32::new(indexer.oldest_ledger)),
                archive_ready: Arc::new(AtomicBool::new(indexer.archive_ready)),
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
                server_task.abort();
                anyhow::bail!("indexer task exited unexpectedly");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received ctrl-c, shutting down");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod network_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[tokio::test]
    async fn startup_retries_unavailable_rpc_but_never_retries_a_mismatch() {
        use std::{sync::atomic::AtomicUsize, time::Duration};
        for passphrase in ["Test SDF Network ; September 2015", "wrong network"] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let requests = attempts.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let app = axum::Router::new().route(
                "/",
                axum::routing::post(move || {
                    let requests = requests.clone();
                    async move {
                        if requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                            return (
                                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                                axum::Json(serde_json::json!({"error": "temporarily unavailable"})),
                            );
                        }
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "jsonrpc":"2.0", "id":1, "result":{"passphrase":passphrase}
                            })),
                        )
                    }
                }),
            );
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            let deployment = read_deployment(
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deployments/testnet"),
            )
            .unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                wait_for_upstream_network_with_backoff(
                    format!("http://{addr}/").parse().unwrap(),
                    &deployment,
                    Duration::from_millis(1),
                    Duration::from_millis(2),
                ),
            )
            .await;
            task.abort();
            let result = result.expect("startup must finish after RPC recovery");
            if passphrase == "wrong network" {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("network passphrase mismatch")
                );
            } else {
                result.expect("matching network resumes startup");
            }
            assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 3);
        }
    }

    #[tokio::test]
    async fn upstream_passphrase_mismatch_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/", axum::routing::post(|| async {
            axum::Json(serde_json::json!({"jsonrpc":"2.0", "id":1, "result":{"passphrase":"wrong network"}}))
        }));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let deployment = read_deployment(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../deployments/testnet/deployments.json"),
        )
        .unwrap();
        let result =
            validate_upstream_network(format!("http://{addr}/").parse().unwrap(), &deployment)
                .await;
        task.abort();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("network passphrase mismatch")
        );
    }
    #[test]
    fn same_binary_loads_two_deployments_with_separate_namespaces() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deployments");
        let mut ids = Vec::new();
        let testnet = read_deployment(&root.join("testnet/deployments.json")).unwrap();
        let mut local = testnet.clone();
        local.network = "local".into();
        local.network_passphrase = Some("Standalone Network ; February 2017".into());
        local.rpc_url = Some("http://localhost:8000/rpc".into());
        for config in [testnet, local] {
            let spec = DeploymentSpec::from_config(&config).unwrap();
            assert!(!spec.network_passphrase.is_empty());
            default_upstream_rpc_url(&config).unwrap();
            ids.push(current_deployment_storage_id(&config).unwrap());
        }
        assert_ne!(ids[0], ids[1]);
        assert!(read_deployment(&root.join("missing-config.json")).is_err());
    }
}
