//! Shared correlation-ID generation and propagation for the SDK.

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

// Per-span bookkeeping used to propagate correlation ids on wasm's
// single-threaded executor. Each span records its parent (as resolved at
// creation time) and, if present, its own correlation id;
// `current_correlation_id` walks the parent chain from the currently
// entered span outward — the same "self + ancestors, innermost first"
// lookup the native path does via `tracing_subscriber::Registry`
// extensions. Unlike a plain push/pop stack of correlation-id *strings*,
// correctness doesn't depend on every enter/exit pair staying in sync: each
// span's correlation id and parent pointer are set once at creation and
// never mutated, so an improperly nested `exit_span` call can only affect which
// span is considered "current" — it can't corrupt another span's own recorded
// correlation id or ancestry.
//
// The parent/correlation maps are kept for every target (a native unit test
// exercises registration/eviction directly); only the "currently entered
// span" stack below is wasm32-only, since native correlation lookups go
// through `CorrelationIdLayer` + `tracing_subscriber::Registry` instead.
thread_local! {
    static SPAN_PARENTS: std::cell::RefCell<std::collections::HashMap<u64, Option<u64>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    static SPAN_CORRELATION: std::cell::RefCell<std::collections::HashMap<u64, String>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

#[cfg(target_arch = "wasm32")]
thread_local! {
    static CURRENT_SPAN_STACK: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Whether `id` currently has bookkeeping recorded (test/diagnostic use).
pub fn has_span(id: u64) -> bool {
    SPAN_PARENTS.with(|p| p.borrow().contains_key(&id))
}

/// Record a newly created span's parent and, if present, its own
/// correlation id, keyed by the subscriber-assigned numeric span id.
pub fn register_span(id: u64, parent: Option<u64>, correlation_id: Option<String>) {
    SPAN_PARENTS.with(|p| p.borrow_mut().insert(id, parent));
    if let Some(corr) = correlation_id {
        SPAN_CORRELATION.with(|c| c.borrow_mut().insert(id, corr));
    }
}

/// Mark `id` as the currently entered span.
#[cfg(target_arch = "wasm32")]
pub fn enter_span(id: u64) {
    CURRENT_SPAN_STACK.with(|stack| stack.borrow_mut().push(id));
}

/// Mark `id` as no longer entered. Removes the innermost matching entry
/// (rather than blindly popping the top) so an improperly nested exit can't
/// evict a still-active ancestor span from the "current" chain.
#[cfg(target_arch = "wasm32")]
pub fn exit_span(id: u64) {
    CURRENT_SPAN_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if let Some(pos) = stack.iter().rposition(|&x| x == id) {
            stack.remove(pos);
        }
    });
}

/// Return the numeric id of the currently entered span, if any.
#[cfg(target_arch = "wasm32")]
pub fn current_span_id() -> Option<u64> {
    CURRENT_SPAN_STACK.with(|stack| stack.borrow().last().copied())
}

/// Drop bookkeeping for a closed span so long-lived tabs don't grow these
/// maps unboundedly.
pub fn evict_span(id: u64) {
    SPAN_PARENTS.with(|p| p.borrow_mut().remove(&id));
    SPAN_CORRELATION.with(|c| c.borrow_mut().remove(&id));
}

#[cfg(not(target_arch = "wasm32"))]
use tracing::{Id, Subscriber, span::Attributes};
#[cfg(not(target_arch = "wasm32"))]
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// A [`tracing_subscriber::Layer`] that caches each span's `correlation_id`
/// field (if any) into that span's extensions at creation time.
#[cfg(not(target_arch = "wasm32"))]
pub struct CorrelationIdLayer;

#[cfg(not(target_arch = "wasm32"))]
struct CorrelationIdVisitor(Option<String>);

#[cfg(not(target_arch = "wasm32"))]
impl tracing::field::Visit for CorrelationIdVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "correlation_id" {
            self.0 = Some(value.to_string());
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "correlation_id" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<S> Layer<S> for CorrelationIdLayer
where
    S: Subscriber + for<'l> LookupSpan<'l>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut v = CorrelationIdVisitor(None);
        attrs.record(&mut v);
        if let Some(corr_id) = v.0
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut().insert(corr_id);
        }
    }
}

/// Return the currently active correlation ID, if any.
pub fn current_correlation_id() -> Option<String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        tracing::dispatcher::get_default(|dispatch| {
            let registry = dispatch.downcast_ref::<tracing_subscriber::Registry>()?;
            let current = dispatch.current_span();
            let id = current.id()?;
            let span = registry.span(id)?;
            span.scope() // self + ancestors, innermost first
                .find_map(|s| s.extensions().get::<String>().cloned())
        })
    }
    #[cfg(target_arch = "wasm32")]
    {
        let mut next = current_span_id();
        while let Some(id) = next {
            if let Some(corr) = SPAN_CORRELATION.with(|c| c.borrow().get(&id).cloned()) {
                return Some(corr);
            }
            next = SPAN_PARENTS.with(|p| p.borrow().get(&id).copied().flatten());
        }
        None
    }
}

/// Get the unique session prefix for this process/isolate.
pub fn session_prefix() -> &'static str {
    static PREFIX: OnceLock<String> = OnceLock::new();
    PREFIX.get_or_init(|| {
        let mut bytes = [0u8; 2];
        if getrandom::getrandom(&mut bytes).is_ok() {
            format!("{:02x}{:02x}", bytes[0], bytes[1])
        } else {
            "0000".to_string()
        }
    })
}

/// Generate a new operation identifier with a collision-safe session prefix.
pub fn new_correlation_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let prefix = session_prefix();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-op-{n}")
}

/// Return the ambient correlation ID if one is already active, otherwise
/// mint a new one.
pub fn correlation_id_or_new() -> String {
    current_correlation_id().unwrap_or_else(new_correlation_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correlation_id_format() {
        let id1 = new_correlation_id();
        let id2 = new_correlation_id();

        let prefix = session_prefix();
        assert_eq!(prefix.len(), 4);

        assert!(id1.starts_with(prefix));
        assert!(id2.starts_with(prefix));
        assert_ne!(id1, id2);

        assert!(id1.contains("-op-"));
        assert!(id2.contains("-op-"));
    }
}
