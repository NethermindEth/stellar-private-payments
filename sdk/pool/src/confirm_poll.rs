//! Delay between transaction confirmation polls (wasm vs native).

use std::time::Duration;

const CONFIRM_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Cooperative async sleep — safe under tokio and pollster (no
/// `thread::sleep`).
pub(crate) async fn sleep_between_confirm_polls() {
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(1_000).await;

    #[cfg(not(target_arch = "wasm32"))]
    futures_timer::Delay::new(CONFIRM_POLL_INTERVAL).await;
}
