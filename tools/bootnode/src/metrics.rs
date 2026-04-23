use anyhow::Result;

pub(crate) fn init_metrics() -> Result<()> {
    // no-op placeholder: kept for symmetry with telemetry init.
    Ok(())
}

pub(crate) fn install_prometheus_recorder() -> Result<metrics_exporter_prometheus::PrometheusHandle> {
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder.install_recorder()?;
    Ok(handle)
}

