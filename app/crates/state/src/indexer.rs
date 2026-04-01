use crate::Storage;
use anyhow::Result;
use crate::contract_events::EventData;

struct Indexer<'a> {
    storage: &'a Storage,
    client: &'a stellar::Client,
}

const PAGE_SIZE: usize = 300;

impl<'a> Indexer {
    pub fn new(storage: &Storage, client: &Client) -> Self<'a> {
        Self {
            storage,
            client
        }
    }

    pub async fn fetch_contract_events(
        &self,
    ) -> Result<()> {
        let mut network_tip = self.get_latest_ledger().await?.sequence;
        // TODO if start is None and cursor is None - we shouldn't start from 0 - we should get some start ledger from a user
        let (start_ledger, mut cursor) = self.storage.get_synced_ledger_and_cursor()?;
        let mut current_ledger = start_ledger.unwrap_or(0);
        while current_ledger < network_tip {
            let (new_cursor, events, latest_ledger) = self.client.get_contract_events(
                contract_ids,
                current_ledger,
                PAGE_SIZE,
                cursor
                ).await?;

            if let Some(last_event) = events.last() {
                // TODO check they ordered by time
                current_ledger = last_event.ledger;
                // TODO how make it async as well? or separate?
                storage.save_events_batch(new_cursor.clone(), &events)?;
            } else {
                current_ledger += 1;
            }
            cursor = new_cursor;
        }

        Ok(())
    }
}
