mod compress;
mod in_memory;
mod postgres;

pub use compress::{CompressStats, PageRecord, plan_empty_compression};
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
    pub last_empty_compress_ledger: u32,
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

/// Result of [`Storage::insert_get_events_page`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertPageOutcome {
    /// New row written.
    Stored,
    /// Existing empty row overwritten with events.
    Replaced,
    /// Duplicate key; existing row left as-is.
    Unchanged {
        /// Whether the retained row already had events.
        existing_had_events: bool,
    },
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn load_kv(&self) -> Result<KvState>;
    async fn update_cursor(&self, cursor: &str) -> Result<()>;
    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()>;
    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()>;
    async fn set_in_sync(&self, in_sync: bool) -> Result<()>;
    async fn set_last_empty_compress_ledger(&self, ledger: u32) -> Result<()>;
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
    /// Replace an existing empty page keyed by `cursor_in` with a non-empty
    /// one.
    ///
    /// Tip empties must not permanently seal a cursor: when upstream later
    /// returns events for the same `cursor_in`, overwrite the empty row.
    async fn replace_empty_page_by_cursor_in(
        &self,
        cursor_in: &str,
        page: InsertGetEventsPage<'_>,
    ) -> Result<()>;
    /// Collapse contiguous empty pages in the handoff window / tip suffix.
    ///
    /// Historical empty runs below `cutoff_ledger` are left alone so cold
    /// clients keep a valid archive cursor chain.
    async fn compress_empty_pages(&self, cutoff_ledger: u32) -> Result<CompressStats>;

    async fn mark_caught_up(&self, cursor: &str, latest_ledger: u32) -> Result<()> {
        self.update_cursor(cursor).await?;
        self.set_last_fully_indexed_ledger(latest_ledger).await?;
        self.set_in_sync(true).await
    }

    async fn insert_get_events_page(
        &self,
        page: InsertGetEventsPage<'_>,
    ) -> Result<InsertPageOutcome> {
        // Persist every page, including empty ones, so upstream cursor chains
        // stay intact. A daily compressor collapses empty spans after tip.
        //
        // Exception: an empty page must not permanently seal a cursor. If a
        // later fetch for the same cursor_in has events, replace the empty.
        if let Some(cursor_in) = page.cursor_in
            && let Some(existing) = self.get_cached_get_events_by_cursor(cursor_in).await?
        {
            let existing_had_events = !existing.events.is_empty();
            if !existing_had_events && !page.result.events.is_empty() {
                self.replace_empty_page_by_cursor_in(cursor_in, page)
                    .await?;
                return Ok(InsertPageOutcome::Replaced);
            }
            return Ok(InsertPageOutcome::Unchanged {
                existing_had_events,
            });
        }
        if page.cursor_in.is_none()
            && let Some(start_ledger) = page.start_ledger
            && let Some(existing) = self
                .get_cached_get_events_by_start_ledger(start_ledger)
                .await?
        {
            return Ok(InsertPageOutcome::Unchanged {
                existing_had_events: !existing.events.is_empty(),
            });
        }

        self.store_get_events_page(page).await?;
        Ok(InsertPageOutcome::Stored)
    }
}
