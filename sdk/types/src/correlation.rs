//! Shared correlation-ID generation and propagation for the SDK.

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

#[cfg(target_arch = "wasm32")]
thread_local! {
    static ACTIVE_CORRELATION_STACK: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(target_arch = "wasm32")]
pub fn push_active_correlation_id(id: String) {
    ACTIVE_CORRELATION_STACK.with(|stack| stack.borrow_mut().push(id));
}

#[cfg(target_arch = "wasm32")]
pub fn pop_active_correlation_id() {
    ACTIVE_CORRELATION_STACK.with(|stack| {
        stack.borrow_mut().pop();
    });
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
        ACTIVE_CORRELATION_STACK.with(|stack| stack.borrow().last().cloned())
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
