#[cfg(target_arch = "wasm32")]
use stellar_private_payments_web::workers::storage::worker_main;

fn main() {
    #[cfg(target_arch = "wasm32")]
    worker_main();
}
