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
        Ok(())
    }

    fn deployment_id(&self) -> &str {
        &self.deployment_id
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
        let client = self.pool.get().await?;
        for event in events {
            let ledger = i32::try_from(event.ledger)
                .context("event ledger exceeds postgres INTEGER range")?;
            client
                .execute(
                    &format!(
                        r#"
INSERT INTO {EVENTS} (deployment_id, id, ledger, payload)
VALUES ($1, $2, $3, $4)
ON CONFLICT (deployment_id, id) DO NOTHING
"#
                    ),
                    &[&self.deployment_id(), &event.id, &ledger, &Json(event)],
                )
                .await?;
        }
        Ok(())
    }

    async fn event_ledger(&self, event_id: &str) -> Result<Option<u32>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                &format!("SELECT ledger FROM {EVENTS} WHERE deployment_id = $1 AND id = $2"),
                &[&self.deployment_id(), &event_id],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let ledger: i32 = row.get(0);
        Ok(Some(
            u32::try_from(ledger.max(0)).context("event ledger exceeds u32 range")?,
        ))
    }

    async fn page_events(
        &self,
        start_ledger: Option<u32>,
        after_event_id: Option<&str>,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<Vec<Event>> {
        let cutoff =
            i32::try_from(cutoff_ledger).context("cutoff_ledger exceeds postgres INTEGER range")?;
        let limit = i64::from(limit);
        let client = self.pool.get().await?;

        let rows = if let Some(after_event_id) = after_event_id {
            let Some(after_ledger) = self.event_ledger(after_event_id).await? else {
                return Ok(Vec::new());
            };
            let after_ledger = i32::try_from(after_ledger)
                .context("after ledger exceeds postgres INTEGER range")?;
            client
                .query(
                    &format!(
                        r#"
SELECT payload FROM {EVENTS}
WHERE deployment_id = $1
  AND ledger < $2
  AND (ledger > $3 OR (ledger = $3 AND id > $4))
ORDER BY ledger, id
LIMIT $5
"#
                    ),
                    &[
                        &self.deployment_id(),
                        &cutoff,
                        &after_ledger,
                        &after_event_id,
                        &limit,
                    ],
                )
                .await?
        } else {
            let start_ledger = i32::try_from(
                start_ledger.context("start_ledger required when after_event_id is absent")?,
            )
            .context("start_ledger exceeds postgres INTEGER range")?;
            client
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
                .await?
        };

        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            let Json(event): Json<Event> = row.get(0);
            events.push(event);
        }
        Ok(events)
    }
}
