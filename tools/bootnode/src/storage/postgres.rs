use super::{InsertGetEventsPage, KvState, Storage};
use anyhow::{Context, Result};
use async_trait::async_trait;
use deadpool_postgres::Pool;
use stellar::GetEventsResponse;
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
CREATE TABLE IF NOT EXISTS bootnode_kv (
  id SMALLINT PRIMARY KEY,
  last_cursor TEXT,
  last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
  ledger_tip INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO bootnode_kv (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'bootnode_kv'
      AND column_name = 'tip_ledger'
  ) THEN
    ALTER TABLE bootnode_kv RENAME COLUMN tip_ledger TO ledger_tip;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS rpc_cache_get_events (
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
CREATE UNIQUE INDEX IF NOT EXISTS rpc_cache_get_events_cursor_in_uniq
  ON rpc_cache_get_events(cursor_in) WHERE cursor_in IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS rpc_cache_get_events_start_ledger_uniq
  ON rpc_cache_get_events(start_ledger) WHERE cursor_in IS NULL;
CREATE INDEX IF NOT EXISTS rpc_cache_get_events_latest_ledger_idx
  ON rpc_cache_get_events(latest_ledger);

CREATE TABLE IF NOT EXISTS cursor_ledger_map (
  cursor TEXT PRIMARY KEY,
  ledger INTEGER NOT NULL
);
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
                "SELECT last_cursor, last_fully_indexed_ledger FROM bootnode_kv WHERE id = 1",
                &[],
            )
            .await?;

        let last_cursor: Option<String> = row.get(0);
        let last_fully_indexed_ledger: i32 = row.get(1);

        Ok(KvState {
            last_cursor,
            last_fully_indexed_ledger: u32::try_from(last_fully_indexed_ledger.max(0))
                .context("last_fully_indexed_ledger exceeds u32 range")?,
        })
    }

    async fn update_cursor(&self, cursor: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE bootnode_kv SET last_cursor = $1, updated_at = now() WHERE id = 1",
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
                "UPDATE bootnode_kv SET last_fully_indexed_ledger = $1, updated_at = now() WHERE id = 1",
                &[&ledger],
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
INSERT INTO rpc_cache_get_events
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

    async fn upsert_cursor_ledger(&self, cursor: &str, ledger: u32) -> Result<()> {
        let ledger = i32::try_from(ledger).context("ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        client
            .execute(
                r#"
INSERT INTO cursor_ledger_map (cursor, ledger)
VALUES ($1, $2)
ON CONFLICT (cursor) DO UPDATE SET ledger = EXCLUDED.ledger
"#,
                &[&cursor, &ledger],
            )
            .await?;
        Ok(())
    }

    async fn lookup_cursor_ledger(&self, cursor: &str) -> Result<Option<u32>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT ledger FROM cursor_ledger_map WHERE cursor = $1",
                &[&cursor],
            )
            .await?;
        Ok(row
            .map(|r| {
                let v: i32 = r.get(0);
                u32::try_from(v.max(0)).context("cursor ledger exceeds u32 range")
            })
            .transpose()?)
    }

    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT result FROM rpc_cache_get_events WHERE cursor_in = $1 LIMIT 1",
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
                "SELECT result FROM rpc_cache_get_events WHERE cursor_in IS NULL AND start_ledger = $1 LIMIT 1",
                &[&start_ledger],
            )
            .await?;
        Ok(row.map(|r| {
            let Json(v): Json<GetEventsResponse> = r.get(0);
            v
        }))
    }
}
