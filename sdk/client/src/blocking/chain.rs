//! Blocking wrappers for the registry / raw-transaction flow.
//!
//! These mirror the async `stellar` helpers but drive them on the shared
//! blocking runtime, so synchronous clients (e.g. the CLI `register` command)
//! do not need their own Tokio runtime.

use anyhow::Result;
use stellar::{
    Client, PreparedSorobanTx, StateFetcher, TransactionEnvelope, TxConfirmStatus,
    confirm_tx as confirm, submit_tx as submit,
};

use super::runtime::block_on;

/// Build the public-key-registry `register` transaction for `source_account`.
pub fn prepare_register(
    fetcher: &StateFetcher,
    source_account: &str,
    note_key: [u8; 32],
    encryption_key: [u8; 32],
) -> Result<PreparedSorobanTx> {
    block_on(fetcher.prepare_register(source_account, note_key, encryption_key))
}

/// Submit a signed transaction; returns its hash.
pub fn submit_tx(signed_tx: &TransactionEnvelope, rpc: &Client) -> Result<String> {
    block_on(submit(signed_tx, rpc))
}

/// Poll a transaction's status once.
pub fn confirm_tx(hash: &str, rpc: &Client) -> Result<TxConfirmStatus> {
    block_on(confirm(hash, rpc))
}
