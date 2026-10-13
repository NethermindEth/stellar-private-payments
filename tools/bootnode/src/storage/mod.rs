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
    /// Added allowlists whose events the archive holds from their deployment
    /// ledger.
    pub archived_allowlists: Vec<String>,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn ping(&self) -> Result<()>;
    async fn load_indexer_state(&self) -> Result<IndexerState>;
    async fn set_last_upstream_cursor(&self, cursor: &str) -> Result<()>;
    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()>;
    async fn set_oldest_ledger(&self, oldest_ledger: u32) -> Result<()>;
    async fn set_archive_ready(&self) -> Result<()>;
    async fn set_archived_allowlists(&self, contract_ids: &[String]) -> Result<()>;
    async fn upsert_events(&self, events: &[Event]) -> Result<()>;
    /// Returns up to `limit` events of `contract_ids` in
    /// `[start_ledger, cutoff_ledger)`, by ledger then ID.
    async fn page_events_ledger(
        &self,
        contract_ids: &[String],
        start_ledger: u32,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<Vec<Event>>;
    /// Like `page_events_ledger`, after event `after_event_id`, whose ledger it
    /// returns. `None` if no event has that ID; it may be any contract's.
    async fn page_events_cursor(
        &self,
        contract_ids: &[String],
        after_event_id: &str,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<(Option<u32>, Vec<Event>)>;
}
