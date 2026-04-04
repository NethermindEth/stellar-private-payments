use gloo_worker::Registrable;

use wasm_bindgen_futures::spawn_local;
use web::init;


fn main() {
    console_error_panic_hook::set_once();
    wasm_log::init(wasm_log::Config::default());
    web::Worker::registrar().register();
    spawn_local(async {
        if let Err(e) = init().await {
            log::error!("[WORKER] init failed: {e:?}");
        }
    });
}
