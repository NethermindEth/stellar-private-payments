use super::tables::SCHEMA_MIGRATIONS;
use anyhow::{Context, Result};
use deadpool_postgres::Client;
use std::collections::HashSet;

const MIGRATIONS: &[(i32, &str)] = &[
    (1, include_str!("001_initial.sql")),
    (2, include_str!("002_event_archive.sql")),
];

pub async fn migrate(client: &mut Client) -> Result<()> {
    client
        .batch_execute(&format!(
            r#"
CREATE TABLE IF NOT EXISTS {SCHEMA_MIGRATIONS} (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#
        ))
        .await?;

    let applied = applied_versions(client).await?;
    for (version, sql) in MIGRATIONS {
        if applied.contains(version) {
            continue;
        }
        let tx = client.transaction().await?;
        tx.batch_execute(sql)
            .await
            .with_context(|| format!("failed applying schema migration {version}"))?;
        tx.execute(
            &format!("INSERT INTO {SCHEMA_MIGRATIONS} (version) VALUES ($1)"),
            &[version],
        )
        .await?;
        tx.commit().await?;
        tracing::info!(version, "applied schema migration");
    }
    Ok(())
}

async fn applied_versions(client: &Client) -> Result<HashSet<i32>> {
    let rows = client
        .query(&format!("SELECT version FROM {SCHEMA_MIGRATIONS}"), &[])
        .await?;
    let mut versions = HashSet::with_capacity(rows.len());
    for row in rows {
        versions.insert(row.get(0));
    }
    Ok(versions)
}
