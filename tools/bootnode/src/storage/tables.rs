//! Postgres object names for bootnode storage. Keep `migrations/*.sql` in sync.

pub(crate) const SCHEMA_MIGRATIONS: &str = "bootnode_schema_migrations";
pub(crate) const STATE: &str = "bootnode_state";
pub(crate) const EVENTS: &str = "bootnode_events";
