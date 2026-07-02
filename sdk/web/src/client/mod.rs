mod core;
mod execute;
mod pool;
mod session;
mod transact;

use stellar_private_payments_sdk::PoolError;
use wasm_bindgen::JsError;

pub use pool::PrivatePool;
pub use session::Client;

pub(crate) use pool::{PoolCreateConfig, build_pool_config};

pub(crate) fn pool_err(error: PoolError) -> JsError {
    use stellar_private_payments_sdk::types::AspMembershipSync;

    match &error {
        PoolError::MembershipSync(AspMembershipSync::RegisterAtASP) => {
            JsError::new("register at ASP before transacting")
        }
        PoolError::MembershipSync(AspMembershipSync::SyncRequired(_)) => {
            JsError::new("indexer sync in progress; try again shortly")
        }
        _ => JsError::new(&error.to_string()),
    }
}

pub(crate) fn pool_err_message(error: PoolError) -> String {
    error.to_string()
}
