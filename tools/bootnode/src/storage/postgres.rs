use super::{
    CompressStats, InsertGetEventsPage, KvState, PageRecord, Storage, plan_empty_compression,
};
use crate::messages::GetEventsResponse;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use deadpool_postgres::{Client, Pool};
use tokio_postgres::types::Json;

pub struct Postgres {
    pool: Pool,
    deployment_id: String,
}

impl Postgres {
    pub async fn connect(
        database_url: &str,
        max_connections: usize,
        deployment_id: impl Into<String>,
    ) -> Result<Self> {
        let pg_cfg: tokio_postgres::Config = database_url
            .parse()
            .context("failed to parse DATABASE_URL")?;
        let mgr = deadpool_postgres::Manager::new(pg_cfg, tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(mgr)
            .max_size(max_connections)
            .build()
            .expect("pool build cannot fail");
        Ok(Self {
            pool,
            deployment_id: deployment_id.into(),
        })
    }

    pub async fn init(&self) -> Result<()> {
        let mut client = self.pool.get().await?;
        migrate(&mut client).await?;
        client
            .execute(
                r#"
INSERT INTO indexer_state (deployment_id) VALUES ($1)
ON CONFLICT (deployment_id) DO NOTHING
"#,
                &[&self.deployment_id],
            )
            .await?;
        Ok(())
    }

    fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    async fn list_pages(&self, client: &Client) -> Result<Vec<PageRecord>> {
        let rows = client
            .query(
                r#"
SELECT id, cursor_in, start_ledger, cursor_out, last_event_ledger, latest_ledger, result
FROM get_events_pages
WHERE deployment_id = $1
ORDER BY id
"#,
                &[&self.deployment_id()],
            )
            .await?;

        let mut pages = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.get(0);
            let cursor_in: Option<String> = row.get(1);
            let start_ledger: Option<i32> = row.get(2);
            let cursor_out: String = row.get(3);
            let last_event_ledger: Option<i32> = row.get(4);
            let latest_ledger: i32 = row.get(5);
            let Json(result): Json<GetEventsResponse> = row.get(6);
            pages.push(PageRecord {
                id,
                cursor_in,
                start_ledger: start_ledger
                    .map(|v| u32::try_from(v.max(0)).context("start_ledger exceeds u32"))
                    .transpose()?,
                cursor_out,
                last_event_ledger: last_event_ledger
                    .map(|v| u32::try_from(v.max(0)).context("last_event_ledger exceeds u32"))
                    .transpose()?,
                latest_ledger: u32::try_from(latest_ledger.max(0))
                    .context("latest_ledger exceeds u32")?,
                result,
            });
        }
        Ok(pages)
    }
}

async fn migrate(client: &mut Client) -> Result<()> {
    client
        .batch_execute(
            r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#,
        )
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
            "INSERT INTO schema_migrations (version) VALUES ($1)",
            &[version],
        )
        .await?;
        tx.commit().await?;
        tracing::info!(version, "applied schema migration");
    }
    Ok(())
}

async fn applied_versions(client: &Client) -> Result<std::collections::HashSet<i32>> {
    let rows = client
        .query("SELECT version FROM schema_migrations", &[])
        .await?;
    let mut versions = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        versions.insert(row.get(0));
    }
    Ok(versions)
}

/// Ordered schema migrations. Each runs at most once inside a transaction.
///
/// Version 1 introduces deployment-namespaced pages + KV. Pre-v1 tables are
/// dropped (no data migration).
/// Version 2 tracks how far empty-page compression has advanced.
const MIGRATIONS: &[(i32, &str)] = &[
    (
        1,
        r#"
DROP TABLE IF EXISTS get_events_pages CASCADE;
DROP TABLE IF EXISTS indexer_state CASCADE;

CREATE TABLE indexer_state (
  deployment_id TEXT PRIMARY KEY,
  last_cursor TEXT,
  last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
  ledger_tip INTEGER NOT NULL DEFAULT 0,
  in_sync BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE get_events_pages (
  id BIGSERIAL PRIMARY KEY,
  deployment_id TEXT NOT NULL,
  cursor_in TEXT,
  start_ledger INTEGER,
  request JSONB NOT NULL,
  result JSONB NOT NULL,
  cursor_out TEXT NOT NULL,
  last_event_ledger INTEGER,
  latest_ledger INTEGER NOT NULL,
  oldest_ledger INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX get_events_pages_deployment_cursor_in_uniq
  ON get_events_pages(deployment_id, cursor_in) WHERE cursor_in IS NOT NULL;
CREATE UNIQUE INDEX get_events_pages_deployment_start_ledger_uniq
  ON get_events_pages(deployment_id, start_ledger) WHERE cursor_in IS NULL;
CREATE INDEX get_events_pages_latest_ledger_idx
  ON get_events_pages(latest_ledger);
CREATE INDEX get_events_pages_cursor_out_ledger_idx
  ON get_events_pages(deployment_id, cursor_out)
  WHERE last_event_ledger IS NOT NULL;
CREATE INDEX get_events_pages_deployment_id_idx
  ON get_events_pages(deployment_id);
"#,
    ),
    (
        2,
        r#"
ALTER TABLE indexer_state
  ADD COLUMN IF NOT EXISTS last_empty_compress_ledger INTEGER NOT NULL DEFAULT 0;
"#,
    ),
];

#[async_trait]
impl Storage for Postgres {
    async fn ping(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client.query_one("SELECT 1", &[]).await?;
        Ok(())
    }

    async fn load_kv(&self) -> Result<KvState> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                r#"
SELECT last_cursor, last_fully_indexed_ledger, ledger_tip, in_sync, last_empty_compress_ledger
FROM indexer_state WHERE deployment_id = $1
"#,
                &[&self.deployment_id()],
            )
            .await?;

        let last_cursor: Option<String> = row.get(0);
        let last_fully_indexed_ledger: i32 = row.get(1);
        let ledger_tip: i32 = row.get(2);
        let in_sync: bool = row.get(3);
        let last_empty_compress_ledger: i32 = row.get(4);

        Ok(KvState {
            last_cursor,
            last_fully_indexed_ledger: u32::try_from(last_fully_indexed_ledger.max(0))
                .context("last_fully_indexed_ledger exceeds u32 range")?,
            ledger_tip: u32::try_from(ledger_tip.max(0)).context("ledger_tip exceeds u32 range")?,
            in_sync,
            last_empty_compress_ledger: u32::try_from(last_empty_compress_ledger.max(0))
                .context("last_empty_compress_ledger exceeds u32 range")?,
        })
    }

    async fn update_cursor(&self, cursor: &str) -> Result<()> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE indexer_state SET last_cursor = $1, updated_at = now() WHERE deployment_id = $2",
                &[&cursor, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()> {
        let ledger = i32::try_from(ledger).context("ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE indexer_state SET last_fully_indexed_ledger = $1, updated_at = now() WHERE deployment_id = $2",
                &[&ledger, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        let ledger_tip =
            i32::try_from(ledger_tip).context("ledger_tip exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE indexer_state SET ledger_tip = $1, updated_at = now() WHERE deployment_id = $2",
                &[&ledger_tip, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn set_in_sync(&self, in_sync: bool) -> Result<()> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE indexer_state SET in_sync = $1, updated_at = now() WHERE deployment_id = $2",
                &[&in_sync, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn set_last_empty_compress_ledger(&self, ledger: u32) -> Result<()> {
        let ledger = i32::try_from(ledger)
            .context("last_empty_compress_ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                "UPDATE indexer_state SET last_empty_compress_ledger = $1, updated_at = now() WHERE deployment_id = $2",
                &[&ledger, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn store_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
        let start_ledger: Option<i32> = page
            .start_ledger
            .map(|ledger| {
                i32::try_from(ledger).context("start_ledger exceeds postgres INTEGER range")
            })
            .transpose()?;
        let last_event_ledger: Option<i32> = page
            .last_event_ledger
            .map(|ledger| {
                i32::try_from(ledger).context("last_event_ledger exceeds postgres INTEGER range")
            })
            .transpose()?;
        let latest_ledger = i32::try_from(page.latest_ledger)
            .context("latest_ledger exceeds postgres INTEGER range")?;
        let oldest_ledger = i32::try_from(page.oldest_ledger)
            .context("oldest_ledger exceeds postgres INTEGER range")?;

        let client = self.pool.get().await?;
        client
            .execute(
                r#"
INSERT INTO get_events_pages
  (deployment_id, cursor_in, start_ledger, request, result, cursor_out, last_event_ledger, latest_ledger, oldest_ledger)
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9)
"#,
                &[
                    &self.deployment_id(),
                    &page.cursor_in,
                    &start_ledger,
                    &Json(page.request),
                    &Json(page.result),
                    &page.cursor_out,
                    &last_event_ledger,
                    &latest_ledger,
                    &oldest_ledger,
                ],
            )
            .await?;
        Ok(())
    }

    async fn replace_empty_page_by_cursor_in(
        &self,
        cursor_in: &str,
        page: InsertGetEventsPage<'_>,
    ) -> Result<()> {
        let last_event_ledger: Option<i32> = page
            .last_event_ledger
            .map(|ledger| {
                i32::try_from(ledger).context("last_event_ledger exceeds postgres INTEGER range")
            })
            .transpose()?;
        let latest_ledger = i32::try_from(page.latest_ledger)
            .context("latest_ledger exceeds postgres INTEGER range")?;
        let oldest_ledger = i32::try_from(page.oldest_ledger)
            .context("oldest_ledger exceeds postgres INTEGER range")?;

        let client = self.pool.get().await?;
        let updated = client
            .execute(
                r#"
UPDATE get_events_pages
SET request = $1,
    result = $2,
    cursor_out = $3,
    last_event_ledger = $4,
    latest_ledger = $5,
    oldest_ledger = $6
WHERE deployment_id = $7 AND cursor_in = $8
"#,
                &[
                    &Json(page.request),
                    &Json(page.result),
                    &page.cursor_out,
                    &last_event_ledger,
                    &latest_ledger,
                    &oldest_ledger,
                    &self.deployment_id(),
                    &cursor_in,
                ],
            )
            .await?;
        if updated != 1 {
            bail!(
                "replace empty page missed cursor_in={cursor_in} deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn lookup_last_event_ledger_for_cursor(&self, cursor: &str) -> Result<Option<u32>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
SELECT last_event_ledger FROM get_events_pages
WHERE deployment_id = $1 AND cursor_out = $2 AND last_event_ledger IS NOT NULL
LIMIT 1
"#,
                &[&self.deployment_id(), &cursor],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let ledger: i32 = row.get(0);
        Ok(Some(
            u32::try_from(ledger.max(0)).context("last_event_ledger exceeds u32 range")?,
        ))
    }

    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT result FROM get_events_pages WHERE deployment_id = $1 AND cursor_in = $2 LIMIT 1",
                &[&self.deployment_id(), &cursor],
            )
            .await?;
        Ok(row.map(|r| {
            let Json(v): Json<GetEventsResponse> = r.get(0);
            v
        }))
    }

    async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>> {
        let start_ledger =
            i32::try_from(start_ledger).context("start_ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT result FROM get_events_pages WHERE deployment_id = $1 AND cursor_in IS NULL AND start_ledger = $2 LIMIT 1",
                &[&self.deployment_id(), &start_ledger],
            )
            .await?;
        Ok(row.map(|r| {
            let Json(v): Json<GetEventsResponse> = r.get(0);
            v
        }))
    }

    async fn compress_empty_pages(&self, cutoff_ledger: u32) -> Result<CompressStats> {
        let mut client = self.pool.get().await?;
        let pages = self.list_pages(&client).await?;
        let plan = plan_empty_compression(&pages, cutoff_ledger);
        if plan.is_empty() {
            return Ok(plan.stats());
        }

        let tx = client.transaction().await?;
        for (id, cursor_out, result, latest_ledger) in &plan.updates {
            let latest_ledger = i32::try_from(*latest_ledger)
                .context("latest_ledger exceeds postgres INTEGER range")?;
            let updated = tx
                .execute(
                    r#"
UPDATE get_events_pages
SET cursor_out = $1, result = $2, latest_ledger = $3
WHERE id = $4 AND deployment_id = $5
"#,
                    &[
                        cursor_out,
                        &Json(result),
                        &latest_ledger,
                        id,
                        &self.deployment_id(),
                    ],
                )
                .await?;
            if updated != 1 {
                bail!("compress update missed page id={id}");
            }
        }
        for id in &plan.deletes {
            let deleted = tx
                .execute(
                    "DELETE FROM get_events_pages WHERE id = $1 AND deployment_id = $2",
                    &[id, &self.deployment_id()],
                )
                .await?;
            if deleted != 1 {
                bail!("compress delete missed page id={id}");
            }
        }
        tx.commit().await?;
        Ok(plan.stats())
    }
}
