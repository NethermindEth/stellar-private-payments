use stellar::{Client, Indexer, TxConfirmStatus, confirm_tx as rpc_confirm_tx};
use types::ContractConfig;

use crate::{Error, Storage, sleep::sleep, types::TransactionResult};

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

/// How the pool keeps local storage in sync with on-chain contract events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// [`crate::Client::sync`] / [`crate::Account::sync`] (and pool reads and
    /// mutations via `ensure_synced`) run deployment catch-up inline.
    Inline,
    /// Storage is kept in sync by a background task you start separately.
    Background,
}

/// Catch local storage up to the current chain tip for a deployment.
pub(crate) async fn catch_up<S: Storage>(
    storage: &S,
    rpc_url: &str,
    contract_config: &ContractConfig,
) -> Result<(), Error> {
    let rpc = Client::new(rpc_url).map_err(|e| Error::Other(format!("rpc client: {e:#}")))?;
    let indexer = Indexer::init(rpc, storage.fork()?, contract_config)
        .await
        .map_err(|e| Error::Other(format!("indexer: {e:#}")))?;
    indexer
        .catch_up()
        .await
        .map_err(|e| Error::Other(format!("indexer catch-up: {e:#}")))?;
    storage.process_pending_state().await
}

/// Poll until a submitted transaction succeeds or fails.
pub(crate) async fn confirm_tx(
    hash: impl AsRef<str>,
    rpc: &Client,
) -> Result<TransactionResult, Error> {
    let hash = hash.as_ref();

    for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
        if attempt > 1 {
            sleep(CONFIRM_POLL_INTERVAL_MS).await;
        }
        match rpc_confirm_tx(hash, rpc)
            .await
            .map_err(|e| Error::Other(format!("confirm transaction: {e:#}")))?
        {
            TxConfirmStatus::Success => {
                return Ok(TransactionResult {
                    tx_hash: hash.to_string(),
                });
            }
            TxConfirmStatus::Failed { detail } => {
                return Err(Error::Other(format!("transaction failed{detail}")));
            }
            TxConfirmStatus::Pending if attempt == CONFIRM_POLL_ATTEMPTS => {
                return Err(Error::Other(format!(
                    "transaction confirmation timed out after 30s (hash: {hash})"
                )));
            }
            TxConfirmStatus::Pending => {}
        }
    }

    Err(Error::Other(format!(
        "transaction confirmation failed (hash: {hash})"
    )))
}
