mod memory;
mod postgres;

pub use memory::Memory;
pub use postgres::Postgres;

use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use stellar::{GetEventsParams, GetEventsResponse};

#[derive(Debug, Clone)]
pub(crate) struct KvState {
    pub(crate) last_cursor: Option<String>,
    pub(crate) last_fully_indexed_ledger: u32,
    pub(crate) ledger_tip: u32,
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
pub trait StorageBackend: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn load_kv(&self) -> Result<KvState>;
    async fn update_ledger_tip(&self, tip: u32) -> Result<()>;
    async fn update_cursor(&self, cursor: &str) -> Result<()>;
    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()>;
    async fn lookup_cursor_ledger(&self, cursor: &str) -> Result<Option<u32>>;
    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>>;
    async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>>;
    async fn store_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()>;
    async fn upsert_cursor_ledger(&self, cursor: &str, ledger: u32) -> Result<()>;

    async fn mark_caught_up(&self, cursor: &str, latest_ledger: u32) -> Result<()> {
        self.update_cursor(cursor).await?;
        self.set_last_fully_indexed_ledger(latest_ledger).await
    }

    async fn insert_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
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

        let cursor_out = page.cursor_out;
        let last_event_ledger = page.last_event_ledger;
        self.store_get_events_page(page).await?;

        if let Some(ledger) = last_event_ledger {
            self.upsert_cursor_ledger(cursor_out, ledger).await?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct Storage {
    inner: Arc<dyn StorageBackend>,
}

impl Storage {
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { inner: backend }
    }

    pub(crate) async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }

    pub(crate) async fn load_kv(&self) -> Result<KvState> {
        self.inner.load_kv().await
    }

    pub(crate) async fn update_ledger_tip(&self, tip: u32) -> Result<()> {
        self.inner.update_ledger_tip(tip).await
    }

    pub(crate) async fn update_cursor(&self, cursor: &str) -> Result<()> {
        self.inner.update_cursor(cursor).await
    }

    pub(crate) async fn mark_caught_up(&self, cursor: &str, latest_ledger: u32) -> Result<()> {
        self.inner.mark_caught_up(cursor, latest_ledger).await
    }

    pub(crate) async fn insert_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
        self.inner.insert_get_events_page(page).await
    }

    pub(crate) async fn lookup_cursor_ledger(&self, cursor: &str) -> Result<Option<u32>> {
        self.inner.lookup_cursor_ledger(cursor).await
    }

    pub(crate) async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>> {
        self.inner.get_cached_get_events_by_cursor(cursor).await
    }

    pub(crate) async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>> {
        self.inner
            .get_cached_get_events_by_start_ledger(start_ledger)
            .await
    }
}
