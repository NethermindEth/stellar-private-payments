use super::{
    CompressStats, InsertGetEventsPage, KvState, PageMeta, Storage, apply_result_cursor,
    plan_empty_compression,
    tables::{GET_EVENTS_PAGES, INDEXER_STATE},
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
        super::migrations::migrate(&mut client).await?;
        client
            .execute(
                &format!(
                    r#"
INSERT INTO {INDEXER_STATE} (deployment_id) VALUES ($1)
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

    async fn list_page_meta(&self, client: &Client) -> Result<Vec<PageMeta>> {
        let rows = client
            .query(
                &format!(
                    r#"
SELECT id, cursor_in, start_ledger, cursor_out, last_event_ledger, latest_ledger
FROM {GET_EVENTS_PAGES}
WHERE deployment_id = $1
ORDER BY id
"#
                ),
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
            pages.push(PageMeta {
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
            });
        }
        Ok(pages)
    }

    async fn load_result(&self, client: &Client, id: i64) -> Result<GetEventsResponse> {
        let row = client
            .query_one(
                &format!(
                    "SELECT result FROM {GET_EVENTS_PAGES} WHERE id = $1 AND deployment_id = $2"
                ),
                &[&id, &self.deployment_id()],
            )
            .await
            .with_context(|| format!("load result for page id={id}"))?;
        let Json(result): Json<GetEventsResponse> = row.get(0);
        Ok(result)
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
                &format!(
                    r#"
SELECT last_cursor, last_fully_indexed_ledger, ledger_tip, in_sync, last_empty_compress_ledger
FROM {INDEXER_STATE} WHERE deployment_id = $1
"#
                ),
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
                &format!(
                    "UPDATE {INDEXER_STATE} SET last_cursor = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&cursor, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "bootnode_indexer_state row missing for deployment_id={}",
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
                &format!(
                    "UPDATE {INDEXER_STATE} SET last_fully_indexed_ledger = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&ledger, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "bootnode_indexer_state row missing for deployment_id={}",
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
                    "UPDATE {INDEXER_STATE} SET ledger_tip = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&ledger_tip, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "bootnode_indexer_state row missing for deployment_id={}",
                self.deployment_id()
            );
        }
        Ok(())
    }

    async fn set_in_sync(&self, in_sync: bool) -> Result<()> {
        let client = self.pool.get().await?;
        let updated = client
            .execute(
                &format!(
                    "UPDATE {INDEXER_STATE} SET in_sync = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&in_sync, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "bootnode_indexer_state row missing for deployment_id={}",
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
                &format!(
                    "UPDATE {INDEXER_STATE} SET last_empty_compress_ledger = $1, updated_at = now() WHERE deployment_id = $2"
                ),
                &[&ledger, &self.deployment_id()],
            )
            .await?;
        if updated != 1 {
            bail!(
                "bootnode_indexer_state row missing for deployment_id={}",
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
                &format!(
                    r#"
INSERT INTO {GET_EVENTS_PAGES}
  (deployment_id, cursor_in, start_ledger, request, result, cursor_out, last_event_ledger, latest_ledger, oldest_ledger)
VALUES
  ($1, $2, $3, $4, $5, $6, $7, $8, $9)
"#
                ),
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
                &format!(
                    r#"
UPDATE {GET_EVENTS_PAGES}
SET request = $1,
    result = $2,
    cursor_out = $3,
    last_event_ledger = $4,
    latest_ledger = $5,
    oldest_ledger = $6
WHERE deployment_id = $7 AND cursor_in = $8
"#
                ),
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
                &format!(
                    r#"
SELECT last_event_ledger FROM {GET_EVENTS_PAGES}
WHERE deployment_id = $1 AND cursor_out = $2 AND last_event_ledger IS NOT NULL
LIMIT 1
"#
                ),
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
                &format!(
                    "SELECT result FROM {GET_EVENTS_PAGES} WHERE deployment_id = $1 AND cursor_in = $2 LIMIT 1"
                ),
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
                &format!(
                    "SELECT result FROM {GET_EVENTS_PAGES} WHERE deployment_id = $1 AND cursor_in IS NULL AND start_ledger = $2 LIMIT 1"
                ),
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
        let pages = self.list_page_meta(&client).await?;
        let plan = plan_empty_compression(&pages, cutoff_ledger);
        if plan.is_empty() {
            return Ok(plan.stats());
        }

        // Load JSONB only for pages whose result will be copied onto a kept row
        // (before deletes in the transaction).
        let mut results = std::collections::HashMap::new();
        for update in &plan.updates {
            if results.contains_key(&update.result_from_id) {
                continue;
            }
            results.insert(
                update.result_from_id,
                self.load_result(&client, update.result_from_id).await?,
            );
        }

        let tx = client.transaction().await?;
        for update in &plan.updates {
            let mut result = results
                .get(&update.result_from_id)
                .cloned()
                .context("missing compress result")?;
            apply_result_cursor(&mut result, &update.cursor_out);
            let latest_ledger = i32::try_from(update.latest_ledger)
                .context("latest_ledger exceeds postgres INTEGER range")?;
            let updated = tx
                .execute(
                    &format!(
                        r#"
UPDATE {GET_EVENTS_PAGES}
SET cursor_out = $1, result = $2, latest_ledger = $3
WHERE id = $4 AND deployment_id = $5 AND last_event_ledger IS NULL
"#
                    ),
                    &[
                        &update.cursor_out,
                        &Json(result),
                        &latest_ledger,
                        &update.id,
                        &self.deployment_id(),
                    ],
                )
                .await?;
            if updated != 1 {
                // Row gone or no longer empty (indexer raced) — roll back.
                bail!(
                    "compress update aborted for page id={} (missing or no longer empty)",
                    update.id
                );
            }
        }
        for id in &plan.deletes {
            let deleted = tx
                .execute(
                    &format!(
                        "DELETE FROM {GET_EVENTS_PAGES} WHERE id = $1 AND deployment_id = $2 AND last_event_ledger IS NULL"
                    ),
                    &[id, &self.deployment_id()],
                )
                .await?;
            if deleted != 1 {
                bail!("compress delete aborted for page id={id} (missing or no longer empty)");
            }
        }
        tx.commit().await?;
        Ok(plan.stats())
    }

    async fn bump_empty_latest_ledger(&self, cursor_in: &str, latest_ledger: u32) -> Result<()> {
        let latest =
            i32::try_from(latest_ledger).context("latest_ledger exceeds postgres INTEGER range")?;
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                &format!(
                    "SELECT result FROM {GET_EVENTS_PAGES} WHERE deployment_id = $1 AND cursor_in = $2 AND last_event_ledger IS NULL LIMIT 1"
                ),
                &[&self.deployment_id(), &cursor_in],
            )
            .await?;
        let Some(row) = row else {
            return Ok(());
        };
        let Json(mut result): Json<GetEventsResponse> = row.get(0);
        result.latest_ledger = latest_ledger;
        let updated = client
            .execute(
                &format!(
                    r#"
UPDATE {GET_EVENTS_PAGES}
SET result = $1, latest_ledger = $2
WHERE deployment_id = $3 AND cursor_in = $4 AND last_event_ledger IS NULL
"#
                ),
                &[&Json(result), &latest, &self.deployment_id(), &cursor_in],
            )
            .await?;
        if updated != 1 {
            bail!("bump empty page missed cursor_in={cursor_in}");
        }
        Ok(())
    }
}
