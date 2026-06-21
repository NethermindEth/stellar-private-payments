use anyhow::Result;

pub fn init_metrics() -> Result<()> {
    Ok(())
}

pub fn install_prometheus_recorder() -> Result<metrics_exporter_prometheus::PrometheusHandle> {
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder.install_recorder()?;
    Ok(handle)
}
