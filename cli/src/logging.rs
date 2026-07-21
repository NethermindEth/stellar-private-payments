//! Progress logging for the CLI.
//!
//! Installs a `tracing` subscriber so SDK sync logs (indexer/storage/transact)
//! and the CLI's own progress lines stream to the user on **stderr**: colored
//! human text by default, or one JSON object per line under `--json` (keeping
//! stdout reserved for the command's JSON result).

use std::io::IsTerminal;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

/// Install the logger. `verbose` is the repeat count of `-v`
/// (0 = info, 1 = debug, 2+ = trace).
pub fn init(verbose: u8, json: bool) {
    // 1. Initialize LogTracer to redirect log::* calls to tracing
    let _ = tracing_log::LogTracer::init();

    // 2. Map verbose level to EnvFilter directives
    let directive = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    // Allow overriding via RUST_LOG environment variable
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(directive));

    let color = !json && std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none();

    // 3. Build the subscriber. CorrelationIdLayer lets nested SDK calls inherit an
    //    ambient correlation_id via correlation_id_or_new() rather than each
    //    minting an unrelated one.
    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(stellar_private_payments_sdk::types::CorrelationIdLayer);

    if json {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .flatten_event(true);
        let _ = subscriber.with(fmt_layer).try_init();
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(color)
            .without_time()
            .with_target(verbose >= 2); // only show targets in trace level
        let _ = subscriber.with(fmt_layer).try_init();
    }
}
