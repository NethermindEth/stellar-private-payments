//! Cross-boundary correlation ID propagation for the web SDK.
//!
//! Public API entry points generate a correlation ID and instrument the
//! futures. The web worker bridges read the current ID and attach it to the
//! request payload; the worker re-attaches it as a tracing span field.

use std::future::Future;
use tracing::Instrument;

// The correlation-id generator, propagation layer, and scope-walk lookup are
// shared with the native SDK; they live in `types` so both crates use one
// implementation. Reached via the client crate re-export so the path
// resolves on native and wasm targets alike.
pub use stellar_private_payments_sdk::types::{current_correlation_id, new_correlation_id};

#[cfg(not(target_arch = "wasm32"))]
#[allow(unused_imports)]
pub use stellar_private_payments_sdk::types::CorrelationIdLayer;

#[cfg(target_arch = "wasm32")]
pub use stellar_private_payments_sdk::types::{
    pop_active_correlation_id, push_active_correlation_id,
};

/// Run a future with `correlation_id` active. Supports nested operations.
pub async fn with_correlation_id<F, R>(id: String, f: F) -> R
where
    F: Future<Output = R>,
{
    let span = tracing::info_span!("operation", correlation_id = %id);
    f.instrument(span).await
}

// Native-only: this test drives a multi-task tokio runtime, which is not
// available on wasm32. `cargo build --tests --target wasm32-unknown-unknown`
// (wasm-bindgen-test) would otherwise fail to resolve `tokio`.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use tracing_subscriber::{Registry, layer::SubscriberExt};

    #[tokio::test]
    async fn test_span_propagation_concurrency() {
        let subscriber = Registry::default().with(CorrelationIdLayer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let id_a = "sessionA-op-1".to_string();
        let id_b = "sessionB-op-2".to_string();

        let handle_a = tokio::spawn(with_correlation_id(id_a.clone(), async move {
            assert_eq!(current_correlation_id(), Some(id_a.clone()));
            tokio::task::yield_now().await;
            assert_eq!(current_correlation_id(), Some(id_a.clone()));

            // Nested check
            let id_nested = "nested-op-3".to_string();
            with_correlation_id(id_nested.clone(), async move {
                assert_eq!(current_correlation_id(), Some(id_nested));
            })
            .await;

            assert_eq!(current_correlation_id(), Some(id_a));
        }));

        let handle_b = tokio::spawn(with_correlation_id(id_b.clone(), async move {
            assert_eq!(current_correlation_id(), Some(id_b.clone()));
            tokio::task::yield_now().await;
            assert_eq!(current_correlation_id(), Some(id_b.clone()));
            assert_eq!(current_correlation_id(), Some(id_b));
        }));

        let (res_a, res_b) = tokio::join!(handle_a, handle_b);
        res_a.expect("thread a finished successfully");
        res_b.expect("thread b finished successfully");
    }
}
