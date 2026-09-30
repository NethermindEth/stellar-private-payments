mod disclaimer;
pub(crate) mod events_parsers;
mod private_vault;
mod processor;
mod public_cache;
mod storage;

pub mod database_key;
pub mod encrypted_migration;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_wallet;
pub mod wallet_vault;

pub use disclaimer::{CURRENT_DISCLAIMER_HASH_HEX, CURRENT_DISCLAIMER_TEXT_MD};
pub use storage::{
    APP_SETTING_BOOTNODE_CONFIG, APP_SETTING_EXPLORER, APP_SETTING_GVK_AUTHORITY,
    DEFAULT_BOOTNODE_URL, Storage, Storage as SqliteStorage, StoredPrivateKeys,
};

mod process_local;
pub(crate) use process_local::process_local_state;
pub use process_local::process_local_state_batch;
