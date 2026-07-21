//! Shared tracing telemetry setup for the web SDK.
//!
//! Provides a single subscriber initialization point used by the main thread
//! (`wasm_start`) and by each web worker. The subscriber consists of:
//!
//! * a standard [`tracing_subscriber::fmt`] layer for browser-console output
//!   (via [`ConsoleMakeWriter`]), so the active span context — including
//!   `correlation_id` — is printed on every line, same as the ring buffer;
//! * an [`EnvFilter`] with a reload handle so the level can be changed at
//!   runtime, and
//! * a bounded in-memory ring buffer that stores recent formatted log lines for
//!   retrieval via [`dump_recent_logs`].
//!
//! The default filter is controlled by the `SPP_LOG_LEVEL` environment
//! variable. In native builds it is read at runtime; in WASM builds it is read
//! at compile time and baked into the binary. If unset, the default is `debug`.
//!
//! Note: this intentionally does not use [`tracing_wasm::WASMLayer`] — that
//! layer's `on_event` only records the event's own fields, never the
//! enclosing span's, so span-only fields like `correlation_id` never reach
//! the console through it.

use std::{
    io::Write,
    sync::{Arc, Mutex, Once},
};
use tracing_subscriber::{
    EnvFilter, Registry, fmt::writer::MakeWriter, layer::SubscriberExt, reload,
    util::SubscriberInitExt,
};

static TELEMETRY_INIT: Once = Once::new();
static PANIC_HOOK_INIT: Once = Once::new();
static FILTER_HANDLE: Mutex<Option<reload::Handle<EnvFilter, Registry>>> = Mutex::new(None);
static RING_BUFFER: Mutex<Option<Arc<RingBuffer>>> = Mutex::new(None);

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

/// Writer that appends to a shared [`RingBuffer`].
#[derive(Clone)]
pub struct RingBufferWriter {
    buffer: Arc<RingBuffer>,
}

impl Write for RingBufferWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.append(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Factory for [`RingBufferWriter`] instances.
#[derive(Clone)]
pub struct RingBufferMakeWriter {
    buffer: Arc<RingBuffer>,
}

impl RingBufferMakeWriter {
    pub fn new(buffer: Arc<RingBuffer>) -> Self {
        Self { buffer }
    }
}

impl<'a> MakeWriter<'a> for RingBufferMakeWriter {
    type Writer = RingBufferWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RingBufferWriter {
            buffer: self.buffer.clone(),
        }
    }
}

/// Writer that buffers one formatted line and flushes it to the browser
/// console (via `web_sys::console`) on drop, using the console method that
/// matches the event's tracing level. Unlike [`tracing_wasm::WASMLayer`],
/// this is fed by the standard `fmt` layer, so the active span context
/// (e.g. `correlation_id`) is included on every line — the same formatting
/// the ring buffer sink uses.
#[cfg(target_arch = "wasm32")]
pub struct ConsoleWriter {
    level: tracing::Level,
    buf: String,
}

#[cfg(target_arch = "wasm32")]
impl Write for ConsoleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.push_str(&String::from_utf8_lossy(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for ConsoleWriter {
    fn drop(&mut self) {
        if self.buf.is_empty() {
            return;
        }
        let line = self.buf.trim_end_matches('\n');
        use wasm_bindgen::JsValue;
        let js_line = JsValue::from_str(line);
        match self.level {
            tracing::Level::ERROR => web_sys::console::error_1(&js_line),
            tracing::Level::WARN => web_sys::console::warn_1(&js_line),
            tracing::Level::INFO => web_sys::console::info_1(&js_line),
            tracing::Level::DEBUG => web_sys::console::debug_1(&js_line),
            tracing::Level::TRACE => web_sys::console::debug_1(&js_line),
        }
    }
}

/// Factory for [`ConsoleWriter`] instances, one per formatted line.
#[cfg(target_arch = "wasm32")]
#[derive(Clone, Default)]
pub struct ConsoleMakeWriter;

#[cfg(target_arch = "wasm32")]
impl<'a> MakeWriter<'a> for ConsoleMakeWriter {
    type Writer = ConsoleWriter;

    fn make_writer(&'a self) -> Self::Writer {
        // Only reached if the subscriber can't determine a level (shouldn't
        // happen via make_writer_for); default to INFO rather than panic.
        ConsoleWriter {
            level: tracing::Level::INFO,
            buf: String::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        ConsoleWriter {
            level: *meta.level(),
            buf: String::new(),
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

    // The ring buffer backs `dump_recent_logs()` — the mechanism a user relies
    // on to attach diagnostic logs to a bug report. It must always be active,
    // independent of build profile or console verbosity, or "collect logs"
    // silently does nothing in a production build.
    let sink = if is_wasm {
        TelemetrySink::Both
    } else {
        TelemetrySink::Console
    };

    let ring_buffer_bytes = if is_test {
        0
    } else {
        256 * 1024 // 256 KiB
    };

    let reveal_sensitive = is_test;

    TelemetryConfig {
        level,
        sink,
        ring_buffer_bytes,
        reveal_sensitive,
    }
}

/// Initialize the tracing subscriber once for the current WASM isolate.
///
/// Safe to call from the main thread or from any worker; the first call in a
/// given isolate installs the subscriber, subsequent calls are no-ops.
pub fn init_telemetry(config: Option<stellar_private_payments_sdk::types::TelemetryConfig>) {
    TELEMETRY_INIT.call_once(|| {
        let config = config.unwrap_or_else(resolve_default_config);

        // Honor the reveal_sensitive configuration
        stellar_private_payments_sdk::types::set_reveal_sensitive(config.reveal_sensitive);

        let _ = tracing_log::LogTracer::init();

        // In release builds, clamp the legacy log facade to info so that
        // third-party log::debug! / log::trace! calls short-circuit before formatting.
        // debug builds keep all levels.
        #[cfg(not(debug_assertions))]
        log::set_max_level(log::LevelFilter::Info);
        #[cfg(debug_assertions)]
        log::set_max_level(log::LevelFilter::Trace);

        // If SPP_LOG_LEVEL is set in env (runtime or compile-time), it overrides
        // config.level
        let level_directive = std::env::var("SPP_LOG_LEVEL")
            .ok()
            .or_else(|| option_env!("SPP_LOG_LEVEL").map(|s| s.to_string()))
            .unwrap_or(config.level);
        let filter =
            EnvFilter::try_new(&level_directive).unwrap_or_else(|_| EnvFilter::new("info"));
        let (filter_layer, reload_handle) = reload::Layer::new(filter);

        let ring_buffer = Arc::new(RingBuffer::new(config.ring_buffer_bytes));

        let use_ring_buffer = config.sink
            == stellar_private_payments_sdk::types::TelemetrySink::RingBuffer
            || config.sink == stellar_private_payments_sdk::types::TelemetrySink::Both;

        let use_console = config.sink
            == stellar_private_payments_sdk::types::TelemetrySink::Console
            || config.sink == stellar_private_payments_sdk::types::TelemetrySink::Both;

        let fmt_layer = if use_ring_buffer {
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(RingBufferMakeWriter::new(ring_buffer.clone()))
                    .without_time(),
            )
        } else {
            None
        };

        #[cfg(target_arch = "wasm32")]
        let console_layer = if use_console {
            Some(
                tracing_subscriber::fmt::layer()
                    .with_writer(ConsoleMakeWriter)
                    .without_time(),
            )
        } else {
            None
        };

        #[cfg(target_arch = "wasm32")]
        let _ = tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .with(console_layer)
            .with(crate::correlation::CorrelationIdLayer)
            .try_init();

        #[cfg(not(target_arch = "wasm32"))]
        let native_console_layer = if use_console {
            Some(tracing_subscriber::fmt::layer())
        } else {
            None
        };

        #[cfg(not(target_arch = "wasm32"))]
        let _ = tracing_subscriber::registry()
            .with(filter_layer)
            .with(fmt_layer)
            .with(native_console_layer)
            .with(crate::correlation::CorrelationIdLayer)
            .try_init();

        *FILTER_HANDLE.lock().expect("filter handle lock poisoned") = Some(reload_handle);
        *RING_BUFFER.lock().expect("ring buffer lock poisoned") = Some(ring_buffer);
    });
}

/// Replace the active [`EnvFilter`] with the supplied directive string.
///
/// Returns an error if telemetry has not been initialized or if the directive
/// is invalid.
pub fn set_log_level(directive: &str) -> Result<(), String> {
    let handle = FILTER_HANDLE
        .lock()
        .expect("filter handle lock poisoned")
        .clone()
        .ok_or("telemetry not initialized")?;
    let new_filter = EnvFilter::try_new(directive).map_err(|e| e.to_string())?;
    handle.reload(new_filter).map_err(|e| e.to_string())?;
    Ok(())
}

/// Return the contents of the recent-log ring buffer as a string.
///
/// Returns an empty string if telemetry has not been initialized.
pub fn dump_recent_logs() -> String {
    RING_BUFFER
        .lock()
        .expect("ring buffer lock poisoned")
        .as_ref()
        .map(|rb| rb.dump())
        .unwrap_or_default()
}

/// Install a panic hook that records the active correlation ID and worker span
/// field before chaining to the previously installed hook.
///
/// Must be called after [`init_telemetry`] so that the panic record is captured
/// by the subscriber and its ring buffer. Safe to call multiple times; the hook
/// is installed only once per WASM isolate.
pub fn install_panic_hook() {
    PANIC_HOOK_INIT.call_once(|| {
        // Start with the console hook so the eventual chain still prints to the
        // browser console, then wrap it to add structured tracing output.
        console_error_panic_hook::set_once();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let correlation_id = crate::correlation::current_correlation_id();
            let message = format!("panic: {info}");
            // Emit within the current span so any active worker field is
            // captured automatically; the event also reaches the ring buffer
            // via the fmt layer installed in `init_telemetry`.
            tracing::error!(correlation_id = ?correlation_id, "{}", message);
            previous(info);
        }));
    });
}

/// Check whether the telemetry subscriber has been initialized.
pub fn is_telemetry_initialized() -> bool {
    FILTER_HANDLE
        .lock()
        .expect("filter handle lock poisoned")
        .is_some()
}
