mod in_memory;
mod migrations;
mod pagination;
mod postgres;
mod tables;

pub use in_memory::InMemory;
pub use pagination::{
    DEFAULT_PAGE_LIMIT, GENESIS_CURSOR_PREFIX, MAX_PAGE_LIMIT, build_response, genesis_cursor,
    page_limit, parse_genesis_cursor,
};
pub use postgres::Postgres;

use crate::messages::Event;
use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct IndexerState {
    pub last_upstream_cursor: Option<String>,
    pub ledger_tip: u32,
    pub oldest_ledger: u32,
    pub archive_ready: bool,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn load_indexer_state(&self) -> Result<IndexerState>;
    async fn set_last_upstream_cursor(&self, cursor: &str) -> Result<()>;
    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()>;
    async fn set_oldest_ledger(&self, oldest_ledger: u32) -> Result<()>;
    async fn set_archive_ready(&self) -> Result<()>;
    async fn upsert_events(&self, events: &[Event]) -> Result<()>;
    async fn event_ledger(&self, event_id: &str) -> Result<Option<u32>>;
    async fn page_events(
        &self,
        start_ledger: Option<u32>,
        after_event_id: Option<&str>,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<Vec<Event>>;
}
