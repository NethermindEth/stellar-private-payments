use super::{
    IndexerState, Storage,
    tables::{EVENTS, STATE},
};
use crate::messages::Event;
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use deadpool_postgres::Pool;
use tokio_postgres::types::Json;

pub struct Postgres {
    pool: Pool,
    deployment_id: String,
    delete_other_deployments: bool,
}

impl Postgres {
    pub async fn connect(
        database_url: &str,
        max_connections: usize,
        deployment_id: impl Into<String>,
        delete_other_deployments: bool,
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
            delete_other_deployments,
        })
    }

    pub async fn init(&self) -> Result<()> {
        let mut client = self.pool.get().await?;
        super::migrations::migrate(&mut client).await?;
        client
            .execute(
                &format!(
                    r#"
INSERT INTO {STATE} (deployment_id) VALUES ($1)
ON CONFLICT (deployment_id) DO NOTHING
"#
                ),
                &[&self.deployment_id],
            )
            .await?;

        if self.delete_other_deployments {
            let (events, state_rows) = self.delete_other_deployment_rows().await?;
            if events > 0 || state_rows > 0 {
                tracing::info!(
                    events,
                    state_rows,
                    deployment_id = self.deployment_id(),
                    "deleted other deployment data"
                );
            }
        }

        Ok(())
    }

    fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    async fn delete_other_deployment_rows(&self) -> Result<(u64, u64)> {
        let client = self.pool.get().await?;
        let events = client
            .execute(
                &format!("DELETE FROM {EVENTS} WHERE deployment_id != $1"),
                &[&self.deployment_id()],
            )
            .await?;
        let state_rows = client
            .execute(
                &format!("DELETE FROM {STATE} WHERE deployment_id != $1"),
                &[&self.deployment_id()],
            )
            .await?;
        Ok((events, state_rows))
    }

    async fn insert_events_batch(
        &self,
        client: &deadpool_postgres::Object,
        events: &[Event],
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let deployment_id = self.deployment_id();
        let mut ids = Vec::with_capacity(events.len());
        let mut ledgers = Vec::with_capacity(events.len());
        let mut payloads = Vec::with_capacity(events.len());

        for event in events {
            ids.push(event.id.as_str());
            ledgers.push(
                i32::try_from(event.ledger)
                    .context("event ledger exceeds postgres INTEGER range")?,
            );
            payloads.push(Json(event));
        }

        client
            .execute(
                &format!(
                    r#"
INSERT INTO {EVENTS} (deployment_id, id, ledger, payload)
SELECT $1, batch.id, batch.ledger, batch.payload
FROM UNNEST($2::text[], $3::int4[], $4::jsonb[]) AS batch(id, ledger, payload)
ON CONFLICT (deployment_id, id) DO NOTHING
"#
                ),
                &[&deployment_id, &ids, &ledgers, &payloads],
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

    async fn load_indexer_state(&self) -> Result<IndexerState> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                &format!(
                    r#"
SELECT last_upstream_cursor, ledger_tip, oldest_ledger, archive_ready
FROM {STATE} WHERE deployment_id = $1
"#
                ),
                &[&self.deployment_id()],
            )
            .await?;

        let last_upstream_cursor: Option<String> = row.get(0);
        let ledger_tip: i32 = row.get(1);
        let oldest_ledger: i32 = row.get(2);
        let archive_ready: bool = row.get(3);

        Ok(IndexerState {
            last_upstream_cursor,
            ledger_tip: u32::try_from(ledger_tip.max(0)).context("ledger_tip exceeds u32")?,
            oldest_ledger: u32::try_from(oldest_ledger.max(0))
                .context("oldest_ledger exceeds u32")?,
            archive_ready,
        })
    }

    async fn set_last_upstream_cursor(&self, cursor: &str) -> Result<()> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                &format!(
                    "UPDATE {STATE} SET last_upstream_cursor = $1, updated_at = now() WHERE deployment_id = $2"
                ),
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

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        let ledger_tip =
            i32::try_from(ledger_tip).context("ledger_tip exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                &format!(
                    "UPDATE {STATE} SET ledger_tip = $1, updated_at = now() WHERE deployment_id = $2"
                ),
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

    async fn set_oldest_ledger(&self, oldest_ledger: u32) -> Result<()> {
        let oldest_ledger =
            i32::try_from(oldest_ledger).context("oldest_ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                &format!(
                    "UPDATE {STATE} SET oldest_ledger = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&oldest_ledger, &self.deployment_id()],
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

    async fn set_archive_ready(&self) -> Result<()> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                &format!(
                    "UPDATE {STATE} SET archive_ready = true, updated_at = now() WHERE deployment_id = $1"
                ),
                &[&self.deployment_id()],
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

    async fn upsert_events(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        const BATCH_SIZE: usize = 1_000;
        let client = self.pool.get().await?;
        for chunk in events.chunks(BATCH_SIZE) {
            self.insert_events_batch(&client, chunk).await?;
        }
        Ok(())
    }

    async fn page_events_ledger(
        &self,
        start_ledger: u32,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<Vec<Event>> {
        let cutoff =
            i32::try_from(cutoff_ledger).context("cutoff_ledger exceeds postgres INTEGER range")?;
        let start_ledger =
            i32::try_from(start_ledger).context("start_ledger exceeds postgres INTEGER range")?;
        let limit = i64::from(limit);
        let client = self.pool.get().await?;

        let rows = client
            .query(
                &format!(
                    r#"
SELECT payload FROM {EVENTS}
WHERE deployment_id = $1
  AND ledger >= $2
  AND ledger < $3
ORDER BY ledger, id
LIMIT $4
"#
                ),
                &[&self.deployment_id(), &start_ledger, &cutoff, &limit],
            )
            .await?;

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let Json(event): Json<Event> = row.get(0);
            events.push(event);
        }
        Ok(events)
    }

    async fn page_events_cursor(
        &self,
        after_event_id: &str,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<(Option<u32>, Vec<Event>)> {
        let cutoff =
            i32::try_from(cutoff_ledger).context("cutoff_ledger exceeds postgres INTEGER range")?;
        let limit = i64::from(limit);
        let client = self.pool.get().await?;

        let rows = client
            .query(
                &format!(
                    r#"
WITH cursor AS (
  SELECT ledger FROM {EVENTS}
  WHERE deployment_id = $1 AND id = $2
)
SELECT c.ledger AS cursor_ledger, e.payload
FROM cursor c
LEFT JOIN LATERAL (
  SELECT payload
  FROM {EVENTS}
  WHERE deployment_id = $1
    AND ledger < $3
    AND (ledger > c.ledger OR (ledger = c.ledger AND id > $2))
  ORDER BY ledger, id
  LIMIT $4
) e ON true
"#
                ),
                &[&self.deployment_id(), &after_event_id, &cutoff, &limit],
            )
            .await?;

        if rows.is_empty() {
            return Ok((None, Vec::new()));
        }

        let cursor_ledger: i32 = rows[0].get(0);
        let cursor_ledger =
            u32::try_from(cursor_ledger.max(0)).context("cursor ledger exceeds u32 range")?;

        let mut events = Vec::new();
        for row in rows {
            let payload: Option<Json<Event>> = row.get(1);
            if let Some(Json(event)) = payload {
                events.push(event);
            }
        }

        Ok((Some(cursor_ledger), events))
    }
}
