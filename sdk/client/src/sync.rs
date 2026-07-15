use stellar::{Client, TxConfirmStatus, confirm_tx as rpc_confirm_tx};

use crate::{Error, sleep::sleep, types::TransactionResult};

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_MS: u32 = 1_000;

/// How the pool keeps local storage in sync with on-chain contract events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// The pool runs [`crate::PrivatePool::sync`] inline when needed.
    /// No separate background sync task is required.
    Inline,
    /// Storage is kept in sync by a background task you start separately.
    Background,
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
