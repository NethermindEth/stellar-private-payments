#[cfg(not(any(feature = "encrypted-storage", feature = "unencrypted-storage")))]
compile_error!("enable at least one of the `encrypted-storage` or `unencrypted-storage` features");

mod disclaimer;
pub(crate) mod events_parsers;
mod preflight;
mod processor;
mod storage;
#[cfg(test)]
mod test_events;

#[cfg(feature = "encrypted-storage")]
pub mod database_key;
#[cfg(all(not(target_arch = "wasm32"), feature = "encrypted-storage"))]
mod encrypted_migration;
#[cfg(all(not(target_arch = "wasm32"), feature = "encrypted-storage"))]
pub mod native_wallet;
#[cfg(all(not(target_arch = "wasm32"), feature = "encrypted-storage"))]
mod wallet_vault;

pub use disclaimer::CURRENT_DISCLAIMER_TEXT_MD;
pub use storage::{
    APP_SETTING_BOOTNODE_CONFIG, APP_SETTING_EXPLORER, APP_SETTING_GVK_AUTHORITY,
    DEFAULT_BOOTNODE_URL, Storage, Storage as SqliteStorage, StoredPrivateKeys,
};

mod process_local;
pub(crate) use process_local::process_local_state;
pub use process_local::process_local_state_batch;

#[cfg(all(test, feature = "encrypted-storage"))]
pub(crate) fn test_storage(path: impl AsRef<std::path::Path>) -> anyhow::Result<SqliteStorage> {
    let path = path.as_ref();
    SqliteStorage::connect_encrypted(
        path,
        &database_key::DatabaseKey::new([42; 32]),
        if path.exists() {
            database_key::OpenPurpose::OpenExisting
        } else {
            database_key::OpenPurpose::CreateNew
        },
    )
}

#[cfg(all(
    test,
    not(feature = "encrypted-storage"),
    feature = "unencrypted-storage"
))]
pub(crate) fn test_storage(path: impl AsRef<std::path::Path>) -> anyhow::Result<SqliteStorage> {
    SqliteStorage::connect_file(path)
}

#[cfg(all(test, feature = "encrypted-storage"))]
pub(crate) fn test_local_storage(path: &str) -> Result<crate::LocalStorage, crate::Error> {
    crate::LocalStorage::open_encrypted(
        path,
        database_key::DatabaseKey::new([42; 32]),
        if std::path::Path::new(path).exists() {
            database_key::OpenPurpose::OpenExisting
        } else {
            database_key::OpenPurpose::CreateNew
        },
    )
}

#[cfg(all(
    test,
    not(feature = "encrypted-storage"),
    feature = "unencrypted-storage"
))]
pub(crate) fn test_local_storage(path: &str) -> Result<crate::LocalStorage, crate::Error> {
    crate::LocalStorage::open(path)
}

/// Legacy plaintext fixture used only by migration tests.
#[cfg(all(test, feature = "encrypted-storage"))]
pub(crate) fn test_plaintext_storage(
    path: impl AsRef<std::path::Path>,
) -> anyhow::Result<SqliteStorage> {
    storage::Storage::connect_with_connection(rusqlite::Connection::open(path)?)
}
