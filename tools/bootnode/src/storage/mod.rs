mod in_memory;
mod postgres;

pub use in_memory::InMemory;
pub use postgres::Postgres;

use crate::messages::{GetEventsParams, GetEventsResponse};
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct KvState {
    pub last_cursor: Option<String>,
    pub last_fully_indexed_ledger: u32,
    pub ledger_tip: u32,
    pub in_sync: bool,
}

pub struct InsertGetEventsPage<'a> {
    pub cursor_in: Option<&'a str>,
    pub start_ledger: Option<u32>,
    pub request: &'a GetEventsParams,
    pub result: &'a GetEventsResponse,
    pub cursor_out: &'a str,
    pub last_event_ledger: Option<u32>,
    pub latest_ledger: u32,
    pub oldest_ledger: u32,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn load_kv(&self) -> Result<KvState>;
    async fn update_cursor(&self, cursor: &str) -> Result<()>;
    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()>;
    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()>;
    async fn set_in_sync(&self, in_sync: bool) -> Result<()>;
    async fn lookup_last_event_ledger_for_cursor(&self, cursor: &str) -> Result<Option<u32>>;
    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>>;
    async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>>;
    async fn store_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()>;

    async fn mark_caught_up(&self, cursor: &str, latest_ledger: u32) -> Result<()> {
        self.update_cursor(cursor).await?;
        self.set_last_fully_indexed_ledger(latest_ledger).await?;
        self.set_in_sync(true).await
    }

    async fn insert_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
        if page.result.events.is_empty() {
            return Ok(());
        }

        if let Some(cursor_in) = page.cursor_in
            && self
                .get_cached_get_events_by_cursor(cursor_in)
                .await?
                .is_some()
        {
            return Ok(());
        }
        if page.cursor_in.is_none()
            && let Some(start_ledger) = page.start_ledger
            && self
                .get_cached_get_events_by_start_ledger(start_ledger)
                .await?
                .is_some()
        {
            return Ok(());
        }

        self.store_get_events_page(page).await?;

        Ok(())
    }
}
