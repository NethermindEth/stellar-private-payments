//! Shared correlation-ID generation and propagation for the SDK.
//!
//! A correlation ID is `<session-prefix>-op-<counter>`: a short
//! per-process/isolate random prefix (collision-safe when logs from the main
//! thread and workers are aggregated) followed by a monotonic per-process
//! counter. Both the native (`sdk/client`) and web (`sdk/web`) crates re-export
//! these so the format and generation live in exactly one place.
//!
//! One ID is minted per public API entry point (CLI command, wasm-bindgen
//! call); everything it calls into should inherit that ID rather than mint
//! its own. Use [`correlation_id_or_new`] wherever a `#[tracing::instrument]`
//! needs a `correlation_id` field but may be called either as the root of an
//! operation (no ambient span yet — mint one) or nested inside one (inherit
//! the ambient one). [`CorrelationIdLayer`] must be part of the subscriber
//! for [`current_correlation_id`] to find anything.

use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use tracing::{Id, Subscriber, span::Attributes};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

/// Get the unique session prefix for this process/isolate.
///
/// Seeded once from `getrandom`; falls back to `"0000"` if the RNG is
/// unavailable.
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

/// A [`tracing_subscriber::Layer`] that caches each span's `correlation_id`
/// field (if any) into that span's extensions at creation time, so
/// [`current_correlation_id`] can find it later via a scope walk. Maintains
/// no mutable "current id" of its own — nothing to corrupt across async
/// yield/resume or interleaved operations.
pub struct CorrelationIdLayer;

struct CorrelationIdVisitor(Option<String>);
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
///
/// Walks the current span's scope (self + ancestors, innermost first) for
/// the nearest span carrying a `correlation_id`. Requires
/// [`CorrelationIdLayer`] to be part of the active subscriber; returns `None`
/// otherwise (e.g. no subscriber installed, or no operation span currently
/// active — such as a background task with no ambient operation).
pub fn current_correlation_id() -> Option<String> {
    tracing::dispatcher::get_default(|dispatch| {
        let registry = dispatch.downcast_ref::<tracing_subscriber::Registry>()?;
        let current = dispatch.current_span();
        let id = current.id()?;
        let span = registry.span(id)?;
        span.scope() // self + ancestors, innermost first
            .find_map(|s| s.extensions().get::<String>().cloned())
    })
}

/// Return the ambient correlation ID if one is already active, otherwise
/// mint a new one.
///
/// Use this — not [`new_correlation_id`] directly — in any
/// `#[tracing::instrument(fields(correlation_id = ...))]` on a function that
/// may be invoked either as the root of an operation (no ambient span yet)
/// or nested inside one already tagged by a caller. Minting unconditionally
/// in the nested case would replace the caller's ID with an unrelated one,
/// breaking correlation across the call.
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
