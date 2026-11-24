//! Threaded prover worker: the serial worker's request handling on top of a
//! rayon thread pool.
//!
//! `wasm-bindgen-rayon` starts the pool from inside this worker. Every pool
//! thread is a nested Web Worker that instantiates this wasm module over the
//! same shared memory, which is why the page has to be cross-origin isolated.
//! wasm-bindgen runs the binary's `main` on the first thread only, so the pool
//! threads never register a worker of their own.
//!
//! Proofs use the SDK's `parallel` proof assembly, which splits
//! each MSM over this pool. `ark-ec`'s own parallel MSM cannot run here: it
//! builds a new pool inside every MSM, which needs `std::thread::spawn`.

use crate::workers::{
    CorrelatedRequest,
    prover::{ProverWorker, ProverWorkerRequest, ProverWorkerResponse},
};
use futures::FutureExt;
use gloo_timers::future::TimeoutFuture;
use gloo_worker::{
    Registrable,
    oneshot::{Oneshot, oneshot},
};
use std::cell::RefCell;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::WorkerGlobalScope;

const WORKER_NAME: &str = "WORKER-PROVER";

/// How long the pool may take to start before proving goes ahead without it.
const POOL_START_TIMEOUT_MS: u32 = 10_000;

enum Pool {
    /// The pool has not been started. `threads` is the size set by
    /// [`ProverWorkerRequest::ConfigureThreads`], if any.
    NotStarted { threads: Option<u32> },
    /// `initThreadPool` is running with `threads` threads. Requests that race
    /// for the first proof all wait on this one promise.
    Starting {
        threads: u32,
        start: js_sys::Promise,
    },
    /// The pool runs with `threads` threads, or will not be started and
    /// `threads` is 1.
    Settled { threads: u32 },
}

thread_local! {
    static POOL: RefCell<Pool> = const { RefCell::new(Pool::NotStarted { threads: None }) };
}

fn global_scope() -> WorkerGlobalScope {
    js_sys::global().unchecked_into()
}

/// One thread per logical core.
// `as` saturates, so a missing or nonsensical `hardwareConcurrency` (NaN,
// negative) becomes 0 and then 1.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn logical_cores(scope: &WorkerGlobalScope) -> u32 {
    (scope.navigator().hardware_concurrency() as u32).max(1)
}

/// Whether the page lets this worker share its memory with other workers.
/// Only an explicit `false` counts as no.
fn cross_origin_isolated(scope: &WorkerGlobalScope) -> bool {
    js_sys::Reflect::get(scope, &"crossOriginIsolated".into())
        .ok()
        .and_then(|isolated| isolated.as_bool())
        .unwrap_or(true)
}

/// Handles [`ProverWorkerRequest::ConfigureThreads`]: sizes the pool, starts
/// it, and returns the number of threads proofs will run on, which is 1 if the
/// pool could not start. Starting it here keeps the start out of the first
/// proof's time budget.
async fn configure_threads(requested: u32) -> Result<u32, String> {
    POOL.with(|pool| match &mut *pool.borrow_mut() {
        Pool::NotStarted { threads } => {
            let cores = logical_cores(&global_scope());
            let size = requested.clamp(1, cores);
            if size != requested {
                tracing::warn!(
                    "[{WORKER_NAME}] {requested} threads requested, using {size} \
                     ({cores} logical cores)"
                );
            }
            *threads = Some(size);
            Ok(())
        }
        Pool::Starting { threads, .. } | Pool::Settled { threads } => Err(format!(
            "the thread pool has already started with {threads} threads; \
             set the thread count before the first proof"
        )),
    })?;
    Ok(ensure_pool().await)
}

/// Starts the rayon pool unless that already happened, and returns the number
/// of threads proofs run on.
///
/// This has to finish before anything uses rayon. Rayon builds its global pool
/// on first use, and with no pool started that is a pool of the calling thread
/// alone, which cannot be replaced afterwards. A pool that fails to start
/// leaves rayon on that same fallback.
async fn ensure_pool() -> u32 {
    let start = POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        match &*pool {
            Pool::Settled { .. } => None,
            Pool::Starting { start, .. } => Some(start.clone()),
            Pool::NotStarted { threads } => {
                let scope = global_scope();
                if !cross_origin_isolated(&scope) {
                    tracing::warn!(
                        "[{WORKER_NAME}] page is not cross-origin isolated, proving on one thread"
                    );
                    *pool = Pool::Settled { threads: 1 };
                    return None;
                }
                let threads = threads.unwrap_or_else(|| logical_cores(&scope));
                let start = wasm_bindgen_rayon::init_thread_pool(threads as usize);
                *pool = Pool::Starting {
                    threads,
                    start: start.clone(),
                };
                Some(start)
            }
        }
    });
    let Some(start) = start else {
        return settled_threads();
    };

    let started = JsFuture::from(start).fuse();
    let timeout = TimeoutFuture::new(POOL_START_TIMEOUT_MS).fuse();
    futures::pin_mut!(started, timeout);
    let outcome = futures::select! {
        result = started => Some(result),
        () = timeout => None,
    };

    // Only the first request to get here settles the pool and reports it.
    let first = POOL.with(|pool| matches!(&*pool.borrow(), Pool::Starting { .. }));
    if !first {
        return settled_threads();
    }
    let threads = match outcome {
        Some(Ok(_)) => {
            // The started pool is rayon's global pool now.
            let threads = u32::try_from(rayon::current_num_threads()).unwrap_or(u32::MAX);
            tracing::info!("[{WORKER_NAME}] rayon pool started with {threads} threads");
            threads
        }
        // Not `rayon::current_num_threads()`: that would set up rayon's
        // fallback pool now, and a start that still finishes later would then
        // fail. The SDK replaces a worker whose pool did not start.
        Some(Err(e)) => {
            tracing::warn!(
                "[{WORKER_NAME}] rayon pool failed to start, proving on one thread: {e:?}"
            );
            1
        }
        None => {
            tracing::warn!(
                "[{WORKER_NAME}] rayon pool did not start within {POOL_START_TIMEOUT_MS} ms, proving on one thread"
            );
            1
        }
    };
    POOL.with(|pool| pool.replace(Pool::Settled { threads }));
    threads
}

/// Threads of a settled pool; 1 while it is still starting.
fn settled_threads() -> u32 {
    POOL.with(|pool| match &*pool.borrow() {
        Pool::Settled { threads } => *threads,
        Pool::NotStarted { .. } | Pool::Starting { .. } => 1,
    })
}

/// Whether `request` builds or runs a prover, which is where rayon is used.
///
/// `VerifyDisclosureProof` counts too: verifying loads the verifying key with
/// validation, and `ark-serialize`'s `parallel` feature, on in this build,
/// checks the key's `gamma_abc_g1` points with rayon (`Valid::batch_check`).
/// Whatever uses rayon first fixes its global pool, so the pool has to be
/// started before.
fn uses_rayon(request: &ProverWorkerRequest) -> bool {
    match request {
        ProverWorkerRequest::Transact(_)
        | ProverWorkerRequest::Disclosure(_)
        | ProverWorkerRequest::VerifyDisclosureProof(..)
        | ProverWorkerRequest::KeyOwnership(_)
        | ProverWorkerRequest::PrepareCircuit(_) => true,
        ProverWorkerRequest::Ping
        | ProverWorkerRequest::ConfigureCircuitsBase(..)
        | ProverWorkerRequest::ConfigureTelemetry(_)
        | ProverWorkerRequest::DumpLogs
        | ProverWorkerRequest::ConfigureThreads(_) => false,
    }
}

pub fn worker_main() {
    let worker_span = tracing::info_span!("worker", worker = "prover-threads");
    {
        let _guard = worker_span.enter();
        crate::telemetry::init_telemetry(None);
        crate::telemetry::install_panic_hook();
        tracing::debug!("[{WORKER_NAME}] ready");
    }
    ThreadedProverWorker::registrar().register();
}

/// Same requests and responses as [`ProverWorker`], so the SDK drives either
/// worker through the same bridge. [`ProverWorkerRequest::ConfigureThreads`]
/// starts the pool; without it, the first request that needs rayon does.
#[oneshot]
pub(crate) async fn ThreadedProverWorker(
    req: CorrelatedRequest<ProverWorkerRequest>,
) -> ProverWorkerResponse {
    if let ProverWorkerRequest::ConfigureThreads(threads) = req.payload {
        return match configure_threads(threads).await {
            Ok(threads) => ProverWorkerResponse::ThreadsConfigured(threads),
            Err(e) => ProverWorkerResponse::Error(e),
        };
    }
    if uses_rayon(&req.payload) {
        let _ = ensure_pool().await;
    }
    <ProverWorker as Oneshot>::create(req).await
}
