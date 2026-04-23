use anyhow::Result;
use deadpool_postgres::Pool;
use tokio_postgres::types::Json;

pub(crate) async fn init_db(pool: &Pool) -> Result<()> {
    let client = pool.get().await?;
    client
        .batch_execute(
            r#"
CREATE TABLE IF NOT EXISTS bootnode_kv (
  id SMALLINT PRIMARY KEY,
  last_cursor TEXT,
  last_fully_indexed_ledger INTEGER NOT NULL DEFAULT 0,
  tip_ledger INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO bootnode_kv (id) VALUES (1)
ON CONFLICT (id) DO NOTHING;

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

#[derive(Debug, Clone)]
pub(crate) struct KvState {
    pub(crate) last_cursor: Option<String>,
    pub(crate) last_fully_indexed_ledger: u32,
    pub(crate) tip_ledger: u32,
}

pub(crate) async fn load_kv(pool: &Pool) -> Result<KvState> {
    let client = pool.get().await?;
    let row = client
        .query_one(
            "SELECT last_cursor, last_fully_indexed_ledger, tip_ledger FROM bootnode_kv WHERE id = 1",
            &[],
        )
        .await?;

    let last_cursor: Option<String> = row.get(0);
    let last_fully_indexed_ledger: i32 = row.get(1);
    let tip_ledger: i32 = row.get(2);

    Ok(KvState {
        last_cursor,
        last_fully_indexed_ledger: last_fully_indexed_ledger.max(0) as u32,
        tip_ledger: tip_ledger.max(0) as u32,
    })
}

pub(crate) async fn update_tip(pool: &Pool, tip: u32) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE bootnode_kv SET tip_ledger = $1, updated_at = now() WHERE id = 1",
            &[&(tip as i64)],
        )
        .await?;
    Ok(())
}

pub(crate) async fn update_cursor(pool: &Pool, cursor: &str) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE bootnode_kv SET last_cursor = $1, updated_at = now() WHERE id = 1",
            &[&cursor],
        )
        .await?;
    Ok(())
}

pub(crate) async fn mark_caught_up(pool: &Pool, cursor: &str, latest_ledger: u32) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            r#"
UPDATE bootnode_kv
SET last_cursor = $1,
    last_fully_indexed_ledger = $2,
    updated_at = now()
WHERE id = 1
"#,
            &[&cursor, &(latest_ledger as i64)],
        )
        .await?;
    Ok(())
}

pub(crate) async fn insert_get_events_page(
    pool: &Pool,
    cursor_in: Option<&str>,
    start_ledger: Option<u32>,
    request: &serde_json::Value,
    result: &serde_json::Value,
    cursor_out: &str,
    last_event_ledger: Option<u32>,
    latest_ledger: u32,
    oldest_ledger: u32,
) -> Result<()> {
    let client = pool.get().await?;
    client
        .execute(
            r#"
INSERT INTO rpc_cache_get_events
  (cursor_in, start_ledger, request, result, cursor_out, last_event_ledger, latest_ledger, oldest_ledger)
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT DO NOTHING
"#,
            &[
                &cursor_in,
                &start_ledger.map(|v| v as i64),
                &Json(request),
                &Json(result),
                &cursor_out,
                &last_event_ledger.map(|v| v as i64),
                &(latest_ledger as i64),
                &(oldest_ledger as i64),
            ],
        )
        .await?;

    if let Some(ledger) = last_event_ledger {
        client
            .execute(
                r#"
INSERT INTO cursor_ledger_map (cursor, ledger)
VALUES ($1, $2)
ON CONFLICT (cursor) DO UPDATE SET ledger = EXCLUDED.ledger
"#,
                &[&cursor_out, &(ledger as i64)],
            )
            .await?;
    }

    Ok(())
}

pub(crate) async fn lookup_cursor_ledger(pool: &Pool, cursor: &str) -> Result<Option<u32>> {
    let client = pool.get().await?;
    let row = client
        .query_opt("SELECT ledger FROM cursor_ledger_map WHERE cursor = $1", &[&cursor])
        .await?;
    Ok(row.map(|r| {
        let v: i32 = r.get(0);
        v.max(0) as u32
    }))
}

pub(crate) async fn get_cached_get_events_by_cursor(
    pool: &Pool,
    cursor: &str,
) -> Result<Option<serde_json::Value>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT result FROM rpc_cache_get_events WHERE cursor_in = $1 LIMIT 1",
            &[&cursor],
        )
        .await?;
    Ok(row.map(|r| {
        let Json(v): Json<serde_json::Value> = r.get(0);
        v
    }))
}

pub(crate) async fn get_cached_get_events_by_start_ledger(
    pool: &Pool,
    start_ledger: u32,
) -> Result<Option<serde_json::Value>> {
    let client = pool.get().await?;
    let row = client
        .query_opt(
            "SELECT result FROM rpc_cache_get_events WHERE cursor_in IS NULL AND start_ledger = $1 LIMIT 1",
            &[&(start_ledger as i64)],
        )
        .await?;
    Ok(row.map(|r| {
        let Json(v): Json<serde_json::Value> = r.get(0);
        v
    }))
}
