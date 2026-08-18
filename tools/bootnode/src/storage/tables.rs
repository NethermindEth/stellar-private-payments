//! Postgres object names for bootnode storage. Keep `migrations/*.sql` in sync.

pub(crate) const SCHEMA_MIGRATIONS: &str = "bootnode_schema_migrations";
pub(crate) const INDEXER_STATE: &str = "bootnode_indexer_state";
pub(crate) const GET_EVENTS_PAGES: &str = "bootnode_get_events_pages";
