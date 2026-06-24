//! WASM indexer storage adapter and pool-local indexer state.

use std::{cell::RefCell, rc::Rc};

use state::Storage;
use stellar::ContractDataStorage;
use types::{ContractsEventData, SyncMetadata};

/// Shared SQLite storage for async [`stellar::Indexer`] on WASM.
#[derive(Clone)]
pub(crate) struct SharedStorage(pub Rc<RefCell<Storage>>);

#[async_trait::async_trait(?Send)]
impl ContractDataStorage for SharedStorage {
    async fn get_sync_state(&self) -> anyhow::Result<Vec<SyncMetadata>> {
        Ok(self.0.borrow().get_sync_metadata()?)
    }

    async fn save_events_batch(&self, batch: ContractsEventData) -> anyhow::Result<()> {
        self.0.borrow_mut().save_events_batch(&batch)?;
        Ok(())
    }

    async fn save_sync_progress(
        &self,
        metadata: Vec<SyncMetadata>,
        fully_indexed: bool,
    ) -> anyhow::Result<()> {
        self.0
            .borrow_mut()
            .save_sync_progress(&metadata, fully_indexed)?;
        Ok(())
    }
}

/// Per-pool WASM indexer state (lazy async init).
pub(crate) struct WasmPoolState {
    pub storage: Rc<RefCell<Storage>>,
    pub indexer: Option<stellar::Indexer<SharedStorage>>,
}
