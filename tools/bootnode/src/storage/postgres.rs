use super::{InsertGetEventsPage, KvState, Storage};
use crate::messages::GetEventsResponse;
use anyhow::{Context, Result};
use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio_postgres::types::Json;

pub struct Postgres {
    pool: Pool,
}

impl Postgres {
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self> {
        let pg_cfg: tokio_postgres::Config = database_url
            .parse()
            .context("failed to parse DATABASE_URL")?;
        let mgr = deadpool_postgres::Manager::new(pg_cfg, tokio_postgres::NoTls);
        let pool = deadpool_postgres::Pool::builder(mgr)
            .max_size(max_connections)
            .build()
            .expect("pool build cannot fail");
        Ok(Self { pool })
    }

    pub async fn init(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .batch_execute(
                r#"
CREATE TABLE IF NOT EXISTS indexer_state (
  id SMALLINT PRIMARY KEY,
  last_cursor TEXT,
  last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
  ledger_tip INTEGER NOT NULL DEFAULT 0,
  in_sync BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO indexer_state (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS get_events_pages (
  id BIGSERIAL PRIMARY KEY,
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
CREATE UNIQUE INDEX IF NOT EXISTS get_events_pages_cursor_in_uniq
  ON get_events_pages(cursor_in) WHERE cursor_in IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS get_events_pages_start_ledger_uniq
  ON get_events_pages(start_ledger) WHERE cursor_in IS NULL;
CREATE INDEX IF NOT EXISTS get_events_pages_latest_ledger_idx
  ON get_events_pages(latest_ledger);
CREATE INDEX IF NOT EXISTS get_events_pages_cursor_out_ledger_idx
  ON get_events_pages(cursor_out)
  WHERE last_event_ledger IS NOT NULL;
"#,
            )
            .await?;
        Ok(())
    }
}

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
                "SELECT last_cursor, last_fully_indexed_ledger, ledger_tip, in_sync FROM indexer_state WHERE id = 1",
                &[],
            )
            .await?;

        let last_cursor: Option<String> = row.get(0);
        let last_fully_indexed_ledger: i32 = row.get(1);
        let ledger_tip: i32 = row.get(2);
        let in_sync: bool = row.get(3);

        Ok(KvState {
            last_cursor,
            last_fully_indexed_ledger: u32::try_from(last_fully_indexed_ledger.max(0))
                .context("last_fully_indexed_ledger exceeds u32 range")?,
            ledger_tip: u32::try_from(ledger_tip.max(0)).context("ledger_tip exceeds u32 range")?,
            in_sync,
        })
    }

    async fn update_cursor(&self, cursor: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE indexer_state SET last_cursor = $1, updated_at = now() WHERE id = 1",
                &[&cursor],
            )
            .await?;
        Ok(())
    }

    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()> {
        let ledger = i32::try_from(ledger).context("ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE indexer_state SET last_fully_indexed_ledger = $1, updated_at = now() WHERE id = 1",
                &[&ledger],
            )
            .await?;
        Ok(())
    }

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        let ledger_tip =
            i32::try_from(ledger_tip).context("ledger_tip exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE indexer_state SET ledger_tip = $1, updated_at = now() WHERE id = 1",
                &[&ledger_tip],
            )
            .await?;
        Ok(())
    }

    async fn set_in_sync(&self, in_sync: bool) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE indexer_state SET in_sync = $1, updated_at = now() WHERE id = 1",
                &[&in_sync],
            )
            .await?;
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
  (cursor_in, start_ledger, request, result, cursor_out, last_event_ledger, latest_ledger, oldest_ledger)
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8)
"#,
                &[
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

    async fn lookup_last_event_ledger_for_cursor(&self, cursor: &str) -> Result<Option<u32>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                r#"
SELECT last_event_ledger FROM get_events_pages
WHERE cursor_out = $1 AND last_event_ledger IS NOT NULL
LIMIT 1
"#,
                &[&cursor],
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
                "SELECT result FROM get_events_pages WHERE cursor_in = $1 LIMIT 1",
                &[&cursor],
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
                "SELECT result FROM get_events_pages WHERE cursor_in IS NULL AND start_ledger = $1 LIMIT 1",
                &[&start_ledger],
            )
            .await?;
        Ok(row.map(|r| {
            let Json(v): Json<GetEventsResponse> = r.get(0);
            v
        }))
    }
}
