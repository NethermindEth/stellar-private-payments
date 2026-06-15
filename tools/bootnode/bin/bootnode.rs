use anyhow::Result;
use bootnode::{Bootnode, config::Config, metrics, otel};

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = Config::parse_and_validate()?;

    let _otel = otel::init_telemetry(&cfg)?;
    metrics::init_metrics()?;
    let prom_handle = metrics::install_prometheus_recorder()?;

    Bootnode::setup(cfg, prom_handle).await?.serve().await
}
