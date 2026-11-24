//! The prover worker with a rayon thread pool; see `workers::prover_threads`.

#[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
use stellar_private_payments_web::workers::prover_threads::worker_main;

fn main() {
    #[cfg(all(target_arch = "wasm32", target_feature = "atomics"))]
    worker_main();

    // Without atomics there is no shared memory to run a pool on, and a worker
    // that never registers would only show up as timeouts.
    #[cfg(all(target_arch = "wasm32", not(target_feature = "atomics")))]
    panic!("prover-worker-threads needs atomics; build it with scripts/build.sh");
}
