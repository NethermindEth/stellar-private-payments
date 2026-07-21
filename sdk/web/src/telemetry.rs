//! Shared tracing telemetry setup for the web SDK.
//!
//! Provides a lightweight subscriber initialization point used by the main
//! thread (`wasm_start`) and by each web worker.

use std::sync::{Arc, Mutex, Once};
use tracing::{Event, Subscriber};
use tracing_subscriber::{
    Layer, Registry,
    layer::{Context, SubscriberExt},
    util::SubscriberInitExt,
};

#[cfg(target_arch = "wasm32")]
use tracing::Level;

static TELEMETRY_INIT: Once = Once::new();
static PANIC_HOOK_INIT: Once = Once::new();
static RING_BUFFER: Mutex<Option<Arc<RingBuffer>>> = Mutex::new(None);
static LOG_LEVEL: Mutex<tracing::level_filters::LevelFilter> =
    Mutex::new(tracing::level_filters::LevelFilter::INFO);

/// Bounded in-memory byte buffer used as a recent-log sink.
pub struct RingBuffer {
    data: Mutex<Vec<u8>>,
    capacity: usize,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }

    pub fn append(&self, bytes: &[u8]) {
        let mut data = self.data.lock().expect("ring buffer lock poisoned");
        data.extend_from_slice(bytes);
        if data.len() > self.capacity {
            let excess = data.len().saturating_sub(self.capacity);
            data.drain(0..excess);
        }
    }

    pub fn dump(&self) -> String {
        let data = self.data.lock().expect("ring buffer lock poisoned");
        String::from_utf8_lossy(&data).into_owned()
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: Vec<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let s = format!("{value:?}");
            if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                self.message = s[1..s.len() - 1].to_string();
            } else {
                self.message = s;
            }
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }
}

/// Minimal, zero-overhead tracing layer for WASM and client logging.
pub struct CustomTelemetryLayer {
    ring_buffer: Option<Arc<RingBuffer>>,
    #[allow(dead_code)]
    use_console: bool,
}

impl<S> Layer<S> for CustomTelemetryLayer
where
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        let current_filter = *LOG_LEVEL.lock().unwrap_or_else(|e| e.into_inner());
        metadata.level() <= &current_filter
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        let mut body = visitor.message;
        if !visitor.fields.is_empty() {
            if !body.is_empty() {
                body.push(' ');
            }
            body.push_str(&visitor.fields.join(" "));
        }

        let correlation = crate::correlation::current_correlation_id();
        let correlation_str = match correlation {
            Some(id) if !id.is_empty() => format!(" [{id}]"),
            _ => String::new(),
        };

        let timestamp = {
            #[cfg(target_arch = "wasm32")]
            {
                js_sys::Date::new_0()
                    .to_iso_string()
                    .as_string()
                    .unwrap_or_default()
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                String::new()
            }
        };

        let ts_str = if timestamp.is_empty() {
            String::new()
        } else {
            format!("[{timestamp}] ")
        };

        let formatted = format!(
            "{ts_str}[{level}]{correlation_str} {body}\n",
            level = event.metadata().level(),
        );

        if let Some(ref rb) = self.ring_buffer {
            rb.append(formatted.as_bytes());
        }

        #[cfg(target_arch = "wasm32")]
        if self.use_console {
            let line = formatted.trim_end_matches('\n');
            let js_line = wasm_bindgen::JsValue::from_str(line);
            match *event.metadata().level() {
                Level::ERROR => web_sys::console::error_1(&js_line),
                Level::WARN => web_sys::console::warn_1(&js_line),
                Level::INFO => web_sys::console::info_1(&js_line),
                Level::DEBUG => web_sys::console::debug_1(&js_line),
                Level::TRACE => web_sys::console::debug_1(&js_line),
            }
        }
    }
}

/// Helper to resolve the default configuration based on build profile and
/// environment.
pub fn resolve_default_config() -> stellar_private_payments_sdk::types::TelemetryConfig {
    use stellar_private_payments_sdk::types::{TelemetryConfig, TelemetrySink};

    let is_wasm = cfg!(target_arch = "wasm32");
    let is_test = cfg!(test);
    let debug_assertions = cfg!(debug_assertions);

    let level = std::env::var("SPP_LOG_LEVEL").unwrap_or_else(|_| {
        if is_test || debug_assertions {
            "debug".to_string()
        } else {
            "info".to_string()
        }
    });

    let sink = if is_wasm {
        TelemetrySink::Both
    } else {
        TelemetrySink::Console
    };

    let ring_buffer_bytes = if is_test { 0 } else { 256 * 1024 };
    let reveal_sensitive = is_test;

    TelemetryConfig {
        level,
        sink,
        ring_buffer_bytes,
        reveal_sensitive,
    }
}

/// Initialize the tracing subscriber once for the current WASM isolate.
pub fn init_telemetry(config: Option<stellar_private_payments_sdk::types::TelemetryConfig>) {
    TELEMETRY_INIT.call_once(|| {
        let config = config.unwrap_or_else(resolve_default_config);

        stellar_private_payments_sdk::types::set_reveal_sensitive(config.reveal_sensitive);

        let _ = tracing_log::LogTracer::init();

        #[cfg(not(debug_assertions))]
        log::set_max_level(log::LevelFilter::Info);
        #[cfg(debug_assertions)]
        log::set_max_level(log::LevelFilter::Trace);

        let level_directive = std::env::var("SPP_LOG_LEVEL")
            .ok()
            .or_else(|| option_env!("SPP_LOG_LEVEL").map(|s| s.to_string()))
            .unwrap_or(config.level);

        let _ = set_log_level(&level_directive);

        let ring_buffer = Arc::new(RingBuffer::new(config.ring_buffer_bytes));

        let use_ring_buffer = config.sink
            == stellar_private_payments_sdk::types::TelemetrySink::RingBuffer
            || config.sink == stellar_private_payments_sdk::types::TelemetrySink::Both;

        let use_console = config.sink
            == stellar_private_payments_sdk::types::TelemetrySink::Console
            || config.sink == stellar_private_payments_sdk::types::TelemetrySink::Both;

        let custom_layer = CustomTelemetryLayer {
            ring_buffer: if use_ring_buffer {
                Some(ring_buffer.clone())
            } else {
                None
            },
            use_console,
        };

        let _ = Registry::default()
            .with(custom_layer)
            .with(crate::correlation::CorrelationIdLayer)
            .try_init();

        *RING_BUFFER.lock().expect("ring buffer lock poisoned") = Some(ring_buffer);
    });
}

/// Replace the active log level filter.
pub fn set_log_level(directive: &str) -> Result<(), String> {
    use std::str::FromStr;
    let filter =
        tracing::level_filters::LevelFilter::from_str(directive).map_err(|e| e.to_string())?;
    *LOG_LEVEL.lock().map_err(|e| e.to_string())? = filter;
    Ok(())
}

/// Return the contents of the recent-log ring buffer as a string.
pub fn dump_recent_logs() -> String {
    RING_BUFFER
        .lock()
        .expect("ring buffer lock poisoned")
        .as_ref()
        .map(|rb| rb.dump())
        .unwrap_or_default()
}

/// Install a panic hook that records the active correlation ID.
pub fn install_panic_hook() {
    PANIC_HOOK_INIT.call_once(|| {
        console_error_panic_hook::set_once();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let correlation_id = crate::correlation::current_correlation_id();
            let message = format!("panic: {info}");
            tracing::error!(correlation_id = ?correlation_id, "{}", message);
            previous(info);
        }));
    });
}

/// Check whether the telemetry subscriber has been initialized.
pub fn is_telemetry_initialized() -> bool {
    RING_BUFFER
        .lock()
        .expect("ring buffer lock poisoned")
        .is_some()
}
