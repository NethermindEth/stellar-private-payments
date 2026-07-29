//! Shared tracing telemetry setup for the web SDK.
//!
//! Provides a lightweight subscriber initialization point used by the main
//! thread (`wasm_start`) and by each web worker.

use std::{
    cell::RefCell,
    sync::{
        Arc, Mutex, Once,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::{
    Event, Id, Metadata, Subscriber,
    span::{Attributes, Record},
};

use crate::{
    protocol::{
        ProverWorkerRequest, ProverWorkerResponse, StorageWorkerRequest, StorageWorkerResponse,
        WorkerTelemetryConfig,
    },
    workers::{prover::ProverBridge, storage::StorageBridge},
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
    correlation_id: Option<String>,
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "correlation_id" {
            self.correlation_id = Some(format!("{value:?}"));
        } else if field.name() == "message" {
            let s = format!("{value:?}");
            if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                let end = s.len().saturating_sub(1);
                self.message = s[1..end].to_string();
            } else {
                self.message = s;
            }
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "correlation_id" {
            self.correlation_id = Some(value.to_string());
        } else if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.push(format!("{}={:?}", field.name(), value));
        }
    }
}

/// Minimal, zero-overhead tracing subscriber for WASM and web logging.
pub struct CustomTelemetrySubscriber {
    ring_buffer: Option<Arc<RingBuffer>>,
    #[allow(dead_code)]
    use_console: bool,
    next_id: AtomicU64,
}

impl CustomTelemetrySubscriber {
    #[allow(dead_code)]
    pub fn new(ring_buffer: Option<Arc<RingBuffer>>, use_console: bool) -> Self {
        Self {
            ring_buffer,
            use_console,
            next_id: AtomicU64::new(0),
        }
    }
}

impl Subscriber for CustomTelemetrySubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let current_filter = *LOG_LEVEL.lock().unwrap_or_else(|e| e.into_inner());
        metadata.level() <= &current_filter
    }

    fn new_span(&self, attrs: &Attributes<'_>) -> Id {
        let mut visitor = MessageVisitor::default();
        attrs.record(&mut visitor);

        let id_val = self
            .next_id
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let id = Id::from_u64(id_val);

        let parent = attrs.parent().map(|p| p.into_u64()).or({
            #[cfg(target_arch = "wasm32")]
            {
                attrs
                    .is_contextual()
                    .then(crate::correlation::current_span_id)
                    .flatten()
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                None
            }
        });
        crate::correlation::register_span(id_val, parent, visitor.correlation_id);

        id
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn enter(&self, _id: &Id) {
        #[cfg(target_arch = "wasm32")]
        crate::correlation::enter_span(_id.into_u64());
    }

    fn exit(&self, _id: &Id) {
        #[cfg(target_arch = "wasm32")]
        crate::correlation::exit_span(_id.into_u64());
    }

    fn try_close(&self, id: Id) -> bool {
        // Evict the span's cached bookkeeping when its refcount reaches
        // zero, so the parent/correlation maps stay bounded in long-lived
        // tabs.
        crate::correlation::evict_span(id.into_u64());
        false
    }

    fn event(&self, event: &Event<'_>) {
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

        let subscriber = CustomTelemetrySubscriber {
            ring_buffer: if use_ring_buffer {
                Some(ring_buffer.clone())
            } else {
                None
            },
            use_console,
            next_id: AtomicU64::new(0),
        };

        let _ = tracing::subscriber::set_global_default(subscriber);

        *RING_BUFFER.lock().expect("ring buffer lock poisoned") = Some(ring_buffer);

        tracing::info!("SDK telemetry initialized");
    });
}

/// Replace the active log level filter.
pub fn set_log_level(directive: &str) -> Result<(), String> {
    use std::str::FromStr;
    let filter =
        tracing::level_filters::LevelFilter::from_str(directive).map_err(|e| e.to_string())?;
    *LOG_LEVEL.lock().map_err(|e| e.to_string())? = filter;
    // tracing caches each callsite's enabled() verdict, so a runtime level
    // change (e.g. the UI log-level select) would otherwise leave already-
    // visited callsites stuck at their old verdict.
    tracing::callsite::rebuild_interest_cache();
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

/// Timeout for telemetry commands (config push, log dump) sent to workers.
/// Short on purpose: diagnostics must never stall application I/O.
const TELEMETRY_CMD_TIMEOUT_MS: u32 = 2_000;

/// A registered worker bridge that receives telemetry configuration pushes
/// and serves log dumps.
#[derive(Clone)]
enum WorkerSink {
    Storage(StorageBridge),
    Prover(ProverBridge),
}

thread_local! {
    static WORKER_SINKS: RefCell<Vec<WorkerSink>> = const { RefCell::new(Vec::new()) };
}

/// Register worker bridges so telemetry configuration and log dumps reach
/// their isolates. Replaces any previously registered sink of the same kind
/// (a new Client means new worker instances) and pushes the current
/// configuration to the freshly registered workers.
pub(crate) fn register_worker_sinks(storage: Option<StorageBridge>, prover: Option<ProverBridge>) {
    WORKER_SINKS.with(|sinks| {
        let mut sinks = sinks.borrow_mut();
        if let Some(storage) = storage {
            sinks.retain(|sink| !matches!(sink, WorkerSink::Storage(_)));
            sinks.push(WorkerSink::Storage(storage));
        }
        if let Some(prover) = prover {
            sinks.retain(|sink| !matches!(sink, WorkerSink::Prover(_)));
            sinks.push(WorkerSink::Prover(prover));
        }
    });
    broadcast_config(current_worker_config());
}

/// The configuration pushed to worker isolates: level and reveal only.
/// Sink targets and ring-buffer sizing stay per-isolate defaults.
pub(crate) fn current_worker_config() -> WorkerTelemetryConfig {
    let level = LOG_LEVEL
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .to_string();
    WorkerTelemetryConfig {
        level,
        reveal_sensitive: stellar_private_payments_sdk::types::reveal_sensitive(),
    }
}

/// Push telemetry configuration to all registered worker isolates.
/// Fire-and-forget: diagnostics must never block or break the caller.
pub(crate) fn broadcast_config(config: WorkerTelemetryConfig) {
    let sinks: Vec<WorkerSink> = WORKER_SINKS.with(|s| s.borrow().clone());
    for sink in sinks {
        let config = config.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let result = match sink {
                WorkerSink::Storage(bridge) => bridge
                    .call(
                        StorageWorkerRequest::ConfigureTelemetry(config),
                        TELEMETRY_CMD_TIMEOUT_MS,
                    )
                    .await
                    .map(|_| ()),
                WorkerSink::Prover(bridge) => bridge
                    .call(
                        ProverWorkerRequest::ConfigureTelemetry(config),
                        TELEMETRY_CMD_TIMEOUT_MS,
                    )
                    .await
                    .map(|_| ()),
            };
            if let Err(e) = result {
                tracing::debug!("telemetry config push to worker failed: {e:#}");
            }
        });
    }
}

/// Aggregate recent logs from the main thread and every registered worker
/// isolate into one string with per-isolate section headers.
pub async fn dump_all_logs() -> String {
    let mut out = String::from("== main ==\n");
    out.push_str(&dump_recent_logs());

    let sinks: Vec<WorkerSink> = WORKER_SINKS.with(|s| s.borrow().clone());
    for sink in sinks {
        let (label, result) = match sink {
            WorkerSink::Storage(bridge) => (
                "storage-worker",
                bridge
                    .call(StorageWorkerRequest::DumpLogs, TELEMETRY_CMD_TIMEOUT_MS)
                    .await
                    .map(|resp| match resp {
                        StorageWorkerResponse::Logs(logs) => logs,
                        other => format!("<unexpected response: {other:?}>"),
                    }),
            ),
            WorkerSink::Prover(bridge) => (
                "prover-worker",
                bridge
                    .call(ProverWorkerRequest::DumpLogs, TELEMETRY_CMD_TIMEOUT_MS)
                    .await
                    .map(|resp| match resp {
                        ProverWorkerResponse::Logs(logs) => logs,
                        other => format!("<unexpected response: {other:?}>"),
                    }),
            ),
        };
        out.push_str(&format!("\n== {label} ==\n"));
        match result {
            Ok(logs) => out.push_str(&logs),
            Err(e) => out.push_str(&format!("<unavailable: {e:#}>\n")),
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that touch the process-global LOG_LEVEL static.
    static TEST_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn span_table_evicts_entry_on_span_close() {
        let _guard = TEST_MUTEX.lock().expect("test mutex poisoned");
        let subscriber = CustomTelemetrySubscriber::new(None, false);
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("operation", correlation_id = "test-correlation-id");
            let id = span.id().expect("span registered").into_u64();
            assert!(crate::correlation::has_span(id));

            drop(span);
            assert!(!crate::correlation::has_span(id));
        });
    }

    #[test]
    fn level_change_applies_to_already_visited_callsites() {
        let _guard = TEST_MUTEX.lock().expect("test mutex poisoned");
        let ring_buffer = Arc::new(RingBuffer::new(4096));
        let subscriber = CustomTelemetrySubscriber::new(Some(ring_buffer.clone()), false);
        tracing::subscriber::with_default(subscriber, || {
            set_log_level("error").expect("set level to error");
            // The loop body is a single callsite visited twice: the first
            // visit is filtered out at error level, the second must be
            // emitted after raising the level to debug.
            for round in 0..2 {
                if round == 1 {
                    set_log_level("debug").expect("set level to debug");
                }
                tracing::debug!("loop callsite event");
            }
            set_log_level("info").expect("restore level");

            let dump = ring_buffer.dump();
            assert_eq!(
                dump.matches("loop callsite event").count(),
                1,
                "only the post-change event should be emitted, got:\n{dump}"
            );
        });
    }
}
