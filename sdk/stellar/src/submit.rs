//! Submit and confirm Soroban transactions via RPC.

use anyhow::{Context, Result, bail};
use stellar_xdr::curr::TransactionEnvelope;

use crate::rpc::Client;

/// Submits a signed transaction; returns the transaction hash.
pub async fn submit_tx(signed_tx: &TransactionEnvelope, rpc: &Client) -> Result<String> {
    let send = rpc
        .send_transaction(signed_tx)
        .await
        .context("sendTransaction failed")?;
    let hash = send.hash;
    if hash.is_empty() {
        bail!("sendTransaction returned empty hash");
    }
    Ok(hash)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxConfirmStatus {
    Success,
    Failed { detail: String },
    Pending,
}

/// Polls transaction status once.
pub async fn confirm_tx(hash: &str, rpc: &Client) -> Result<TxConfirmStatus> {
    let status = rpc
        .get_transaction(hash)
        .await
        .with_context(|| format!("getTransaction failed for {hash}"))?;
    map_transaction_status(&status.status, status.result_xdr)
}

fn map_transaction_status(status: &str, result_xdr: Option<String>) -> Result<TxConfirmStatus> {
    match status {
        "SUCCESS" => Ok(TxConfirmStatus::Success),
        "FAILED" => {
            let detail = result_xdr
                .map(|xdr| format!(" (resultXdr: {xdr})"))
                .unwrap_or_default();
            Ok(TxConfirmStatus::Failed { detail })
        }
        _ => Ok(TxConfirmStatus::Pending),
    }
}

/// Synchronous submit and confirm (native targets only).
#[cfg(not(target_arch = "wasm32"))]
pub mod blocking {
    use super::*;
    use crate::rpc::blocking::Client;

    /// Submits a signed transaction; returns the transaction hash.
    pub fn submit_tx(signed_tx: &TransactionEnvelope, rpc: &Client) -> Result<String> {
        let send = rpc
            .send_transaction(signed_tx)
            .context("sendTransaction failed")?;
        let hash = send.hash;
        if hash.is_empty() {
            bail!("sendTransaction returned empty hash");
        }
        Ok(hash)
    }

    /// Polls transaction status once.
    pub fn confirm_tx(hash: &str, rpc: &Client) -> Result<TxConfirmStatus> {
        let status = rpc
            .get_transaction(hash)
            .with_context(|| format!("getTransaction failed for {hash}"))?;
        map_transaction_status(&status.status, status.result_xdr)
    }
}
