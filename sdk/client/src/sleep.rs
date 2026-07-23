//! Target-specific async sleep.

pub(crate) async fn sleep(millis: u32) {
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::TimeoutFuture::new(millis).await;

    #[cfg(not(target_arch = "wasm32"))]
    futures_timer::Delay::new(std::time::Duration::from_millis(u64::from(millis))).await;
}
