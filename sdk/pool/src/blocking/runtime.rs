use std::{future::Future, sync::OnceLock};

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    RUNTIME
        .get_or_init(|| {
            Runtime::new().expect("failed to initialize tokio runtime for blocking SDK API")
        })
        .block_on(future)
}
