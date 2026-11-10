use anyhow::{Context, Result};
use axum::{Router, routing::get};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::{future::ready, net::SocketAddr, time::Duration};

/// Installs the global metrics recorder and serves the recorded metrics at
/// `/metrics` on `addr`.
///
/// Returns once `addr` is bound; the listener and upkeep run as background
/// tasks.
///
/// # Errors
///
/// Returns an error if `addr` cannot be bound or a recorder is already
/// installed.
pub async fn serve(addr: SocketAddr) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind metrics listener {addr}"))?;
    let handle = PrometheusBuilder::new().install_recorder()?;
    let upkeep = handle.clone();
    // `install_recorder` leaves draining histogram samples to the caller.
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            upkeep.run_upkeep();
        }
    });
    let app = Router::new().route("/metrics", get(move || ready(handle.render())));
    tracing::info!(bind = %addr, "serving metrics");
    tokio::spawn(axum::serve(listener, app).into_future());
    Ok(())
}
