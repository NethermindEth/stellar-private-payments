use anyhow::Result;
use rusqlite::{Connection, params};
use rusqlite_migration::{M, Migrations};

const DB_NAME: &str = "spp.sqlite";

const MIGRATION_ARRAY: &[M] = &[M::up(include_str!("schema.sql"))];
const MIGRATIONS: Migrations = Migrations::from_slice(MIGRATION_ARRAY);

pub fn init_db() -> Result<Connection> {
    let mut conn = Connection::open(DB_NAME)?;
    MIGRATIONS.to_latest(&mut conn)?;

    conn.pragma_update(None, "foreign_keys", "ON")?;

    Ok(conn)
}
