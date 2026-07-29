pub mod pool;
pub mod seed;

/// Initialize a tracing subscriber that writes to the test output stream.
///
/// This is intended for integration tests so that failures emit an execution
/// trace even when captured by the test harness. Includes
/// [`types::CorrelationIdLayer`] so `correlation_id_or_new()` correctly
/// inherits an ambient ID within a test. Subsequent calls are ignored if a
/// subscriber is already installed.
pub fn init_test_tracing() {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(tracing_subscriber::fmt::writer::TestWriter::new());
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(types::CorrelationIdLayer)
        .try_init();
}

#[cfg(test)]
mod tests;
