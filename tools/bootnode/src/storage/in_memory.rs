use super::{InsertGetEventsPage, KvState, Storage};
use crate::messages::GetEventsResponse;
use anyhow::Result;
use async_trait::async_trait;
use std::{collections::HashMap, sync::Mutex};

#[derive(Default)]
struct State {
    last_cursor: Option<String>,
    last_fully_indexed_ledger: u32,
    ledger_tip: u32,
    in_sync: bool,
    cache_by_cursor_in: HashMap<String, GetEventsResponse>,
    cache_by_start_ledger: HashMap<u32, GetEventsResponse>,
    ledger_by_cursor_out: HashMap<String, u32>,
}

pub struct InMemory {
    state: Mutex<State>,
}

impl InMemory {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_state<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        let state = self.state.lock().expect("in-memory storage mutex poisoned");
        f(&state)
    }

    fn with_state_mut<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut state = self.state.lock().expect("in-memory storage mutex poisoned");
        f(&mut state)
    }
}

impl Default for InMemory {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }
}

#[async_trait]
impl Storage for InMemory {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn load_kv(&self) -> Result<KvState> {
        Ok(self.with_state(|state| KvState {
            last_cursor: state.last_cursor.clone(),
            last_fully_indexed_ledger: state.last_fully_indexed_ledger,
            ledger_tip: state.ledger_tip,
            in_sync: state.in_sync,
        }))
    }

    async fn update_cursor(&self, cursor: &str) -> Result<()> {
        self.with_state_mut(|state| state.last_cursor = Some(cursor.to_owned()));
        Ok(())
    }

    async fn set_last_fully_indexed_ledger(&self, ledger: u32) -> Result<()> {
        self.with_state_mut(|state| state.last_fully_indexed_ledger = ledger);
        Ok(())
    }

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        self.with_state_mut(|state| state.ledger_tip = ledger_tip);
        Ok(())
    }

    async fn set_in_sync(&self, in_sync: bool) -> Result<()> {
        self.with_state_mut(|state| state.in_sync = in_sync);
        Ok(())
    }

    async fn lookup_last_event_ledger_for_cursor(&self, cursor: &str) -> Result<Option<u32>> {
        Ok(self.with_state(|state| state.ledger_by_cursor_out.get(cursor).copied()))
    }

    async fn get_cached_get_events_by_cursor(
        &self,
        cursor: &str,
    ) -> Result<Option<GetEventsResponse>> {
        Ok(self.with_state(|state| state.cache_by_cursor_in.get(cursor).cloned()))
    }

    async fn store_get_events_page(&self, page: InsertGetEventsPage<'_>) -> Result<()> {
        self.with_state_mut(|state| {
            if let Some(cursor_in) = page.cursor_in {
                state
                    .cache_by_cursor_in
                    .insert(cursor_in.to_owned(), page.result.clone());
            } else if let Some(start_ledger) = page.start_ledger {
                state
                    .cache_by_start_ledger
                    .insert(start_ledger, page.result.clone());
            }
            if let Some(ledger) = page.last_event_ledger {
                state
                    .ledger_by_cursor_out
                    .insert(page.cursor_out.to_owned(), ledger);
            }
        });
        Ok(())
    }

    async fn get_cached_get_events_by_start_ledger(
        &self,
        start_ledger: u32,
    ) -> Result<Option<GetEventsResponse>> {
        Ok(self.with_state(|state| state.cache_by_start_ledger.get(&start_ledger).cloned()))
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

    #[tokio::test]
    async fn cache_round_trip_and_kv_updates() {
        let storage = InMemory::new();
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
        let storage = InMemory::new();
        storage.set_ledger_tip(3_000_000).await.expect("set tip");

        let kv = storage.load_kv().await.expect("load kv");
        assert_eq!(kv.ledger_tip, 3_000_000);
    }

    #[tokio::test]
    async fn duplicate_insert_is_ignored() {
        let storage = InMemory::new();
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
}
