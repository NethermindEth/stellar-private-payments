use anyhow::Result;
use bootnode::{build_state, config::Config, metrics, otel, serve};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Arc::new(Config::parse_and_validate()?);

    let _otel = otel::init_telemetry(&cfg)?;
    metrics::init_metrics()?;
    let prom_handle = metrics::install_prometheus_recorder()?;

    let state = build_state(cfg, prom_handle).await?;
    serve(state).await
}
