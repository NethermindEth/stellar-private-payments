use super::{
    CompressStats, InsertGetEventsPage, KvState, PageMeta, Storage, apply_result_cursor,
    plan_empty_compression,
};
use crate::messages::GetEventsResponse;
use anyhow::{Result, bail};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
struct StoredPage {
    meta: PageMeta,
    result: GetEventsResponse,
}

#[derive(Default)]
struct DeploymentState {
    last_cursor: Option<String>,
    last_fully_indexed_ledger: u32,
    ledger_tip: u32,
    in_sync: bool,
    last_empty_compress_ledger: u32,
    next_page_id: i64,
    pages: Vec<StoredPage>,
    cache_by_cursor_in: HashMap<String, GetEventsResponse>,
    cache_by_start_ledger: HashMap<u32, GetEventsResponse>,
    ledger_by_cursor_out: HashMap<String, u32>,
}

#[derive(Default)]
struct Shared {
    by_deployment: HashMap<String, DeploymentState>,
}

pub struct InMemory {
    shared: Arc<Mutex<Shared>>,
    deployment_id: String,
}

impl InMemory {
    /// Storage scoped to the compiled-in deployment.
    pub fn new() -> Self {
        let deployment_id = crate::current_deployment_storage_id()
            .expect("compiled-in deployment config must be valid");
        Self::with_deployment_id(deployment_id)
    }

    pub fn with_deployment_id(deployment_id: impl Into<String>) -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
            deployment_id: deployment_id.into(),
        }
    }

    /// Another deployment namespace on the same shared backend.
    pub fn scope(&self, deployment_id: impl Into<String>) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            deployment_id: deployment_id.into(),
        }
    }

    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    fn with_deployment<R>(&self, f: impl FnOnce(&DeploymentState) -> R) -> R {
        let mut shared = self
            .shared
            .lock()
            .expect("in-memory storage mutex poisoned");
        let state = shared
            .by_deployment
            .entry(self.deployment_id.clone())
            .or_default();
        f(state)
    }

    fn with_deployment_mut<R>(&self, f: impl FnOnce(&mut DeploymentState) -> R) -> R {
        let mut shared = self
            .shared
            .lock()
            .expect("in-memory storage mutex poisoned");
        let state = shared
            .by_deployment
            .entry(self.deployment_id.clone())
            .or_default();
        f(state)
    }
}

impl Default for InMemory {
    fn default() -> Self {
        Self::new()
    }
}

fn rebuild_indexes(state: &mut DeploymentState) {
    state.cache_by_cursor_in.clear();
    state.cache_by_start_ledger.clear();
    state.ledger_by_cursor_out.clear();
    for page in &state.pages {
        if let Some(cursor_in) = page.meta.cursor_in.as_deref() {
            state
                .cache_by_cursor_in
                .insert(cursor_in.to_owned(), page.result.clone());
        } else if let Some(start_ledger) = page.meta.start_ledger {
            state
                .cache_by_start_ledger
                .insert(start_ledger, page.result.clone());
        }
        if let Some(ledger) = page.meta.last_event_ledger {
            state
                .ledger_by_cursor_out
                .insert(page.meta.cursor_out.clone(), ledger);
        }
    }
}

fn apply_compress_plan(
    state: &mut DeploymentState,
    plan: &super::compress::CompressPlan,
) -> Result<CompressStats> {
    // Abort if any target row is gone or no longer empty (indexer race).
    for update in &plan.updates {
        let keep_empty = state
            .pages
            .iter()
            .find(|p| p.meta.id == update.id)
            .is_some_and(|p| p.meta.last_event_ledger.is_none());
        if !keep_empty {
            bail!(
                "compress update aborted for page id={} (missing or no longer empty)",
                update.id
            );
        }
        let source_empty = state
            .pages
            .iter()
            .find(|p| p.meta.id == update.result_from_id)
            .is_some_and(|p| p.meta.last_event_ledger.is_none());
        if !source_empty {
            bail!(
                "compress update aborted for result source id={} (missing or no longer empty)",
                update.result_from_id
            );
        }
    }
    for id in &plan.deletes {
        let still_empty = state
            .pages
            .iter()
            .find(|p| p.meta.id == *id)
            .is_some_and(|p| p.meta.last_event_ledger.is_none());
        if !still_empty {
            bail!("compress delete aborted for page id={id} (missing or no longer empty)");
        }
    }

    let delete: std::collections::HashSet<i64> = plan.deletes.iter().copied().collect();
    let results: HashMap<i64, GetEventsResponse> = state
        .pages
        .iter()
        .filter(|p| plan.updates.iter().any(|u| u.result_from_id == p.meta.id))
        .map(|p| (p.meta.id, p.result.clone()))
        .collect();
    let updates: HashMap<i64, _> = plan.updates.iter().map(|u| (u.id, u)).collect();

    state.pages.retain_mut(|page| {
        if delete.contains(&page.meta.id) {
            return false;
        }
        if let Some(update) = updates.get(&page.meta.id) {
            page.meta.cursor_out = update.cursor_out.clone();
            page.meta.latest_ledger = update.latest_ledger;
            let mut result = results
                .get(&update.result_from_id)
                .cloned()
                .expect("compress result_from_id");
            apply_result_cursor(&mut result, &update.cursor_out);
            page.result = result;
        }
        true
    });
    rebuild_indexes(state);
    Ok(plan.stats())
}

#[async_trait]
impl Storage for InMemory {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn load_kv(&self) -> Result<KvState> {
        Ok(self.with_deployment(|state| KvState {
            last_cursor: state.last_cursor.clone(),
            last_fully_indexed_ledger: state.last_fully_indexed_ledger,
            ledger_tip: state.ledger_tip,
            in_sync: state.in_sync,
            last_empty_compress_ledger: state.last_empty_compress_ledger,
        }))
    }

    async fn update_cursor(&self, cursor: &str) -> Result<()> {
        self.with_deployment_mut(|state| state.last_cursor = Some(cursor.to_owned()));
        Ok(())
    }

    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()> {
        self.with_deployment_mut(|state| state.last_fully_indexed_ledger = ledger);
        Ok(())
    }

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        self.with_deployment_mut(|state| state.ledger_tip = ledger_tip);
        Ok(())
    }

    async fn set_in_sync(&self, in_sync: bool) -> Result<()> {
        self.with_deployment_mut(|state| state.in_sync = in_sync);
        Ok(())
    }

    async fn set_last_empty_compress_ledger(&self, ledger: u32) -> Result<()> {
        self.with_deployment_mut(|state| state.last_empty_compress_ledger = ledger);
        Ok(())
    }

    async fn lookup_last_event_ledger_for_cursor(&self, cursor: &str) -> Result<Option<u32>> {
        Ok(self.with_deployment(|state| state.ledger_by_cursor_out.get(cursor).copied()))
    }

    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>> {
        Ok(self.with_deployment(|state| state.cache_by_cursor_in.get(cursor).cloned()))
    }

    async fn store_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
        self.with_deployment_mut(|state| {
            state.next_page_id = state.next_page_id.saturating_add(1);
            let id = state.next_page_id;
            state.pages.push(StoredPage {
                meta: PageMeta {
                    id,
                    cursor_in: page.cursor_in.map(str::to_owned),
                    start_ledger: page.start_ledger,
                    cursor_out: page.cursor_out.to_owned(),
                    last_event_ledger: page.last_event_ledger,
                    latest_ledger: page.latest_ledger,
                },
                result: page.result.clone(),
            });
            rebuild_indexes(state);
        });
        Ok(())
    }

    async fn replace_empty_page_by_cursor_in(
        &self,
        cursor_in: &str,
        page: InsertGetEventsPage<'_>,
    ) -> Result<()> {
        self.with_deployment_mut(|state| {
            let Some(existing) = state
                .pages
                .iter_mut()
                .find(|p| p.meta.cursor_in.as_deref() == Some(cursor_in))
            else {
                return;
            };
            existing.meta.cursor_out = page.cursor_out.to_owned();
            existing.meta.last_event_ledger = page.last_event_ledger;
            existing.meta.latest_ledger = page.latest_ledger;
            existing.result = page.result.clone();
            rebuild_indexes(state);
        });
        Ok(())
    }

    async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>> {
        Ok(self.with_deployment(|state| state.cache_by_start_ledger.get(&start_ledger).cloned()))
    }

    async fn compress_empty_pages(&self, cutoff_ledger: u32) -> Result<CompressStats> {
        let plan = self.with_deployment(|state| {
            let meta: Vec<PageMeta> = state.pages.iter().map(|p| p.meta.clone()).collect();
            plan_empty_compression(&meta, cutoff_ledger)
        });
        if plan.is_empty() {
            return Ok(plan.stats());
        }
        self.with_deployment_mut(|state| apply_compress_plan(state, &plan))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{Event, GetEventsParams, GetEventsResponse, PaginationParams};
    use serde_json::json;

    fn sample_page<'a>(
        cursor_in: Option<&'a str>,
        start_ledger: Option<u32>,
        cursor_out: &'a str,
        result: &'a GetEventsResponse,
    ) -> InsertGetEventsPage<'a> {
        static REQUEST: GetEventsParams = GetEventsParams {
            filters: vec![],
            pagination: PaginationParams {
                limit: None,
                cursor: None,
            },
            start_ledger: None,
            end_ledger: None,
            xdr_format: None,
        };

        InsertGetEventsPage {
            cursor_in,
            start_ledger,
            request: &REQUEST,
            result,
            cursor_out,
            last_event_ledger: Some(42),
            latest_ledger: 100,
            oldest_ledger: 1,
        }
    }

    fn empty_insert<'a>(
        cursor_in: Option<&'a str>,
        start_ledger: Option<u32>,
        cursor_out: &'a str,
        latest_ledger: u32,
        result: &'a GetEventsResponse,
    ) -> InsertGetEventsPage<'a> {
        static REQUEST: GetEventsParams = GetEventsParams {
            filters: vec![],
            pagination: PaginationParams {
                limit: None,
                cursor: None,
            },
            start_ledger: None,
            end_ledger: None,
            xdr_format: None,
        };
        InsertGetEventsPage {
            cursor_in,
            start_ledger,
            request: &REQUEST,
            result,
            cursor_out,
            last_event_ledger: None,
            latest_ledger,
            oldest_ledger: 1,
        }
    }

    fn sample_event() -> Event {
        serde_json::from_value(json!({
            "type": "contract",
            "ledger": 42,
            "ledgerClosedAt": "2024-01-01T00:00:00Z",
            "contractId": "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM",
            "id": "event-1",
            "topic": [],
            "value": "00",
        }))
        .expect("sample event")
    }

    fn sample_response(cursor: &str, latest_ledger: u32) -> GetEventsResponse {
        GetEventsResponse {
            cursor: cursor.to_string(),
            events: vec![sample_event()],
            latest_ledger,
            latest_ledger_close_time: "2024-01-01T00:00:00Z".to_string(),
            oldest_ledger: 1,
            oldest_ledger_close_time: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    fn empty_response(cursor: &str, latest_ledger: u32) -> GetEventsResponse {
        GetEventsResponse {
            cursor: cursor.to_string(),
            events: vec![],
            latest_ledger,
            latest_ledger_close_time: "2024-01-01T00:00:00Z".to_string(),
            oldest_ledger: 1,
            oldest_ledger_close_time: "2024-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn empty_pages_are_persisted() {
        let storage = InMemory::with_deployment_id("test");
        let empty = empty_response("empty-out", 100);

        storage
            .insert_get_events_page(empty_insert(
                Some("cursor-in"),
                None,
                "empty-out",
                100,
                &empty,
            ))
            .await
            .expect("insert empty page");

        let cached = storage
            .get_cached_get_events_by_cursor("cursor-in")
            .await
            .expect("lookup")
            .expect("empty page must be cached for cursor continuity");
        assert!(cached.events.is_empty());
        assert_eq!(cached.cursor, "empty-out");
    }

    #[tokio::test]
    async fn compress_leaves_historical_empty_run_below_cutoff() {
        let storage = InMemory::with_deployment_id("test");
        let p1 = empty_response("c1", 400);
        let p2 = empty_response("c2", 500);
        let p3 = empty_response("c3", 590);

        storage
            .insert_get_events_page(empty_insert(None, Some(100), "c1", 400, &p1))
            .await
            .expect("insert c1");
        storage
            .insert_get_events_page(empty_insert(Some("c1"), None, "c2", 500, &p2))
            .await
            .expect("insert c2");
        storage
            .insert_get_events_page(empty_insert(Some("c2"), None, "c3", 590, &p3))
            .await
            .expect("insert c3");

        let stats = storage.compress_empty_pages(600).await.expect("compress");
        assert_eq!(stats.spans_joined, 0);
        assert_eq!(stats.pages_removed, 0);

        assert_eq!(
            storage
                .get_cached_get_events_by_start_ledger(100)
                .await
                .expect("lookup root")
                .expect("root")
                .cursor,
            "c1"
        );
        assert!(
            storage
                .get_cached_get_events_by_cursor("c1")
                .await
                .expect("lookup c1")
                .is_some()
        );
    }

    #[tokio::test]
    async fn compress_merges_tip_suffix_in_handoff_window() {
        let storage = InMemory::with_deployment_id("test");
        let events = sample_response("e1", 550);
        let p1 = empty_response("c1", 650);
        let p2 = empty_response("c2", 700);

        storage
            .insert_get_events_page({
                let mut page = sample_page(None, Some(100), "e1", &events);
                page.last_event_ledger = Some(550);
                page.latest_ledger = 550;
                page
            })
            .await
            .expect("insert events");
        storage
            .insert_get_events_page(empty_insert(Some("e1"), None, "c1", 650, &p1))
            .await
            .expect("insert c1");
        storage
            .insert_get_events_page(empty_insert(Some("c1"), None, "c2", 700, &p2))
            .await
            .expect("insert c2");

        let stats = storage.compress_empty_pages(600).await.expect("compress");
        assert_eq!(stats.spans_joined, 1);
        assert_eq!(stats.pages_removed, 1);

        let kept = storage
            .get_cached_get_events_by_cursor("e1")
            .await
            .expect("lookup")
            .expect("merged empty");
        assert_eq!(kept.cursor, "c2");
        assert!(kept.events.is_empty());
        assert!(
            storage
                .get_cached_get_events_by_cursor("c1")
                .await
                .expect("lookup c1")
                .is_none()
        );
    }

    #[tokio::test]
    async fn compress_aborts_if_delete_target_gained_events() {
        let storage = InMemory::with_deployment_id("test");
        let events = sample_response("e1", 550);
        let p1 = empty_response("c1", 650);
        let p2 = empty_response("c2", 700);

        storage
            .insert_get_events_page({
                let mut page = sample_page(None, Some(100), "e1", &events);
                page.last_event_ledger = Some(550);
                page.latest_ledger = 550;
                page
            })
            .await
            .expect("insert events");
        storage
            .insert_get_events_page(empty_insert(Some("e1"), None, "c1", 650, &p1))
            .await
            .expect("insert c1");
        storage
            .insert_get_events_page(empty_insert(Some("c1"), None, "c2", 700, &p2))
            .await
            .expect("insert c2");

        // Snapshot a plan that would delete the tip empty, then fill that row
        // (simulates indexer racing after plan, before apply).
        let plan = storage.with_deployment(|state| {
            let meta: Vec<PageMeta> = state.pages.iter().map(|p| p.meta.clone()).collect();
            plan_empty_compression(&meta, 600)
        });
        assert_eq!(plan.updates.len(), 1);
        assert_eq!(plan.deletes.len(), 1);

        let filled = sample_response("after", 700);
        storage
            .replace_empty_page_by_cursor_in("c1", {
                let mut page = sample_page(Some("c1"), None, "after", &filled);
                page.last_event_ledger = Some(700);
                page.latest_ledger = 700;
                page
            })
            .await
            .expect("fill empty");

        let err = storage
            .with_deployment_mut(|state| apply_compress_plan(state, &plan))
            .expect_err("must abort when delete target has events");
        assert!(
            err.to_string().contains("aborted"),
            "unexpected error: {err:#}"
        );
        assert!(
            !storage
                .get_cached_get_events_by_cursor("c1")
                .await
                .expect("lookup")
                .expect("events must remain")
                .events
                .is_empty()
        );
    }

    #[tokio::test]
    async fn cache_round_trip_and_kv_updates() {
        let storage = InMemory::with_deployment_id("test");
        let result = sample_response("next", 100);

        storage
            .insert_get_events_page(sample_page(None, Some(10), "next", &result))
            .await
            .expect("insert should succeed");
        storage
            .mark_caught_up("next", 100)
            .await
            .expect("mark caught up");

        let cached = storage
            .get_cached_get_events_by_start_ledger(10)
            .await
            .expect("lookup should succeed")
            .expect("page should be cached");
        assert_eq!(cached.cursor, "next");

        let kv = storage.load_kv().await.expect("load kv");
        assert_eq!(kv.last_cursor.as_deref(), Some("next"));
        assert_eq!(kv.last_fully_indexed_ledger, 100);
        assert!(kv.in_sync);

        let last_event_ledger = storage
            .lookup_last_event_ledger_for_cursor("next")
            .await
            .expect("lookup last event ledger");
        assert_eq!(last_event_ledger, Some(42));
    }

    #[tokio::test]
    async fn ledger_tip_persists_in_kv() {
        let storage = InMemory::with_deployment_id("test");
        storage.set_ledger_tip(3_000_000).await.expect("set tip");

        let kv = storage.load_kv().await.expect("load kv");
        assert_eq!(kv.ledger_tip, 3_000_000);
    }

    #[tokio::test]
    async fn duplicate_insert_is_ignored() {
        let storage = InMemory::with_deployment_id("test");
        let first = sample_response("first", 1);
        let second = sample_response("second", 2);

        storage
            .insert_get_events_page(sample_page(Some("in"), None, "first", &first))
            .await
            .expect("first insert");
        storage
            .insert_get_events_page(sample_page(Some("in"), None, "second", &second))
            .await
            .expect("duplicate insert");

        let cached = storage
            .get_cached_get_events_by_cursor("in")
            .await
            .expect("lookup")
            .expect("cached");
        assert_eq!(cached.cursor, "first");
    }

    #[tokio::test]
    async fn empty_page_replaced_when_events_arrive() {
        let storage = InMemory::with_deployment_id("test");
        let empty = empty_response("tip", 100);
        let with_events = sample_response("after", 110);

        storage
            .insert_get_events_page(empty_insert(Some("tip"), None, "tip", 100, &empty))
            .await
            .expect("insert empty tip");
        storage
            .insert_get_events_page(sample_page(Some("tip"), None, "after", &with_events))
            .await
            .expect("replace with events");

        let cached = storage
            .get_cached_get_events_by_cursor("tip")
            .await
            .expect("lookup")
            .expect("cached");
        assert_eq!(cached.cursor, "after");
        assert_eq!(cached.events.len(), 1);

        let last_event = storage
            .lookup_last_event_ledger_for_cursor("after")
            .await
            .expect("lookup last event");
        assert_eq!(last_event, Some(42));
    }

    #[tokio::test]
    async fn deployments_are_isolated() {
        let a = InMemory::with_deployment_id("dep-a");
        let b = a.scope("dep-b");

        let page_a = sample_response("cursor-a", 10);
        let page_b = sample_response("cursor-b", 20);

        a.insert_get_events_page(sample_page(None, Some(100), "cursor-a", &page_a))
            .await
            .expect("insert a");
        b.insert_get_events_page(sample_page(None, Some(100), "cursor-b", &page_b))
            .await
            .expect("insert b");

        let from_a = a
            .get_cached_get_events_by_start_ledger(100)
            .await
            .expect("lookup a")
            .expect("a page");
        let from_b = b
            .get_cached_get_events_by_start_ledger(100)
            .await
            .expect("lookup b")
            .expect("b page");
        assert_eq!(from_a.cursor, "cursor-a");
        assert_eq!(from_b.cursor, "cursor-b");

        a.mark_caught_up("cursor-a", 10).await.expect("kv a");
        b.mark_caught_up("cursor-b", 20).await.expect("kv b");
        assert_eq!(
            a.load_kv().await.expect("load a").last_cursor.as_deref(),
            Some("cursor-a")
        );
        assert_eq!(
            b.load_kv().await.expect("load b").last_cursor.as_deref(),
            Some("cursor-b")
        );
    }
}
