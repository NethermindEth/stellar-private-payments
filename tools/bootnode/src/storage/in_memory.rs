use super::{IndexerState, Storage};
use crate::messages::Event;
use anyhow::Result;
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct DeploymentState {
    last_upstream_cursor: Option<String>,
    ledger_tip: u32,
    oldest_ledger: u32,
    archive_ready: bool,
    archived_allowlists: Vec<String>,
    events: BTreeMap<(u32, String), Event>,
}

#[derive(Default)]
struct Shared {
    by_deployment: std::collections::HashMap<String, DeploymentState>,
}

pub struct InMemory {
    shared: Arc<Mutex<Shared>>,
    deployment_id: String,
}

impl InMemory {
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

#[async_trait]
impl Storage for InMemory {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn load_indexer_state(&self) -> Result<IndexerState> {
        Ok(self.with_deployment(|state| IndexerState {
            last_upstream_cursor: state.last_upstream_cursor.clone(),
            ledger_tip: state.ledger_tip,
            oldest_ledger: state.oldest_ledger,
            archive_ready: state.archive_ready,
            archived_allowlists: state.archived_allowlists.clone(),
        }))
    }

    async fn set_last_upstream_cursor(&self, cursor: &str) -> Result<()> {
        self.with_deployment_mut(|state| state.last_upstream_cursor = Some(cursor.to_owned()));
        Ok(())
    }

    async fn set_ledger_tip(&self, ledger_tip: u32) -> Result<()> {
        self.with_deployment_mut(|state| state.ledger_tip = ledger_tip);
        Ok(())
    }

    async fn set_oldest_ledger(&self, oldest_ledger: u32) -> Result<()> {
        self.with_deployment_mut(|state| state.oldest_ledger = oldest_ledger);
        Ok(())
    }

    async fn set_archive_ready(&self) -> Result<()> {
        self.with_deployment_mut(|state| state.archive_ready = true);
        Ok(())
    }

    async fn set_archived_allowlists(&self, contract_ids: &[String]) -> Result<()> {
        self.with_deployment_mut(|state| state.archived_allowlists = contract_ids.to_vec());
        Ok(())
    }

    async fn upsert_events(&self, events: &[Event]) -> Result<()> {
        self.with_deployment_mut(|state| {
            for event in events {
                state
                    .events
                    .entry((event.ledger, event.id.clone()))
                    .or_insert_with(|| event.clone());
            }
        });
        Ok(())
    }

    async fn page_events_ledger(
        &self,
        contract_ids: &[String],
        start_ledger: u32,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<Vec<Event>> {
        Ok(self.with_deployment(|state| {
            let mut events: Vec<Event> = state
                .events
                .values()
                .filter(|event| event.ledger < cutoff_ledger && event.ledger >= start_ledger)
                .filter(|event| contract_ids.contains(&event.contract_id))
                .cloned()
                .collect();
            events.sort_by(|left, right| {
                left.ledger
                    .cmp(&right.ledger)
                    .then_with(|| left.id.cmp(&right.id))
            });
            events.truncate(limit as usize);
            events
        }))
    }

    async fn page_events_cursor(
        &self,
        contract_ids: &[String],
        after_event_id: &str,
        cutoff_ledger: u32,
        limit: u32,
    ) -> Result<(Option<u32>, Vec<Event>)> {
        Ok(self.with_deployment(|state| {
            let Some(after_ledger) = state
                .events
                .values()
                .find(|event| event.id == after_event_id)
                .map(|event| event.ledger)
            else {
                return (None, Vec::new());
            };

            let mut events: Vec<Event> = state
                .events
                .values()
                .filter(|event| event.ledger < cutoff_ledger)
                .filter(|event| contract_ids.contains(&event.contract_id))
                .filter(|event| {
                    event.id != after_event_id
                        && (event.ledger > after_ledger
                            || (event.ledger == after_ledger && event.id.as_str() > after_event_id))
                })
                .cloned()
                .collect();
            events.sort_by(|left, right| {
                left.ledger
                    .cmp(&right.ledger)
                    .then_with(|| left.id.cmp(&right.id))
            });
            events.truncate(limit as usize);
            (Some(after_ledger), events)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::Event;
    use serde_json::json;

    const POOL: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";
    const OTHER: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCT4";

    fn sample_event(id: &str, ledger: u32, contract_id: &str) -> Event {
        serde_json::from_value(json!({
            "type": "contract",
            "ledger": ledger,
            "ledgerClosedAt": "2024-01-01T00:00:00Z",
            "contractId": contract_id,
            "id": id,
            "topic": [],
            "value": "00",
        }))
        .expect("sample event")
    }

    #[tokio::test]
    async fn page_events_respects_cutoff_cursor_and_contracts() {
        let storage = InMemory::with_deployment_id("test-deployment");
        storage
            .upsert_events(&[
                sample_event("event-a", 100, POOL),
                sample_event("event-o1", 150, OTHER),
                sample_event("event-b", 200, POOL),
                sample_event("event-o2", 300, OTHER),
                sample_event("event-c", 500, POOL),
                sample_event("event-d", 700, POOL),
            ])
            .await
            .expect("seed");
        let pool = [POOL.to_string()];

        let first = storage
            .page_events_ledger(&pool, 100, 400, 10)
            .await
            .expect("first page");
        let ids: Vec<&str> = first.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["event-a", "event-b"]);

        // The limit counts only the requested contract's events.
        let limited = storage
            .page_events_ledger(&pool, 100, 400, 2)
            .await
            .expect("limited page");
        let ids: Vec<&str> = limited.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["event-a", "event-b"]);

        // The cursor may be another contract's event.
        let (cursor_ledger, second) = storage
            .page_events_cursor(&pool, "event-o1", 600, 10)
            .await
            .expect("second page");
        let ids: Vec<&str> = second.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(cursor_ledger, Some(150));
        assert_eq!(ids, ["event-b", "event-c"]);
    }
}
