use crate::config::Config;
use anyhow::Result;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::{Resource, trace as sdktrace};
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub(crate) struct TelemetryGuard {
    provider: sdktrace::SdkTracerProvider,
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        let _ = self.provider.shutdown();
    }
}

pub(crate) fn init_telemetry(cfg: &Config) -> Result<Option<TelemetryGuard>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true);

    if !cfg.otel_enabled {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .init();
        return Ok(None);
    }

    let endpoint = cfg
        .otel_otlp_endpoint
        .clone()
        .unwrap_or_else(|| "http://localhost:4317".to_string());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .with_timeout(Duration::from_secs(5))
        .build()?;

    let resource = Resource::builder()
        .with_service_name(cfg.otel_service_name.clone())
        .build();

    let provider = sdktrace::SdkTracerProvider::builder()
        .with_resource(resource)
        .with_sampler(sdktrace::Sampler::TraceIdRatioBased(cfg.otel_sample_ratio))
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer("bootnode");
    opentelemetry::global::set_tracer_provider(provider.clone());

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    Ok(Some(TelemetryGuard { provider }))
}
