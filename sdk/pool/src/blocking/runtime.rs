use std::{future::Future, sync::OnceLock};

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

const INSIDE_TOKIO_RUNTIME_PANIC: &str = "\
blocking::PrivatePool cannot be used inside a Tokio runtime; \
use stellar_private_payments_sdk::PrivatePool instead.";

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "{INSIDE_TOKIO_RUNTIME_PANIC}"
    );

    RUNTIME
        .get_or_init(|| {
            Runtime::new().expect("failed to initialize tokio runtime for blocking SDK API")
        })
        .block_on(future)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_on_sync_context() {
        assert_eq!(block_on(async { 42 }), 42);
    }

    #[test]
    #[should_panic]
    fn block_on_tokio_runtime() {
        let runtime = Runtime::new().expect("test runtime");
        runtime.block_on(async {
            block_on(async { 42 });
        });
    }
}
