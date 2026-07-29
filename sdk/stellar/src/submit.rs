//! Submit and confirm Soroban transactions via RPC.

use anyhow::{Context, Result, bail};
use stellar_xdr::TransactionEnvelope;

use crate::rpc::Client;

/// Submits a signed transaction; returns the transaction hash.
#[tracing::instrument(name = "submit_tx", level = "info", skip_all, fields(correlation_id = %types::correlation_id_or_new()))]
pub async fn submit_tx(rpc: &Client, signed_tx: &TransactionEnvelope) -> Result<String> {
    let send = rpc
        .send_transaction(signed_tx)
        .await
        .context("sendTransaction failed")?;
    let hash = send.hash;
    if hash.is_empty() {
        bail!("sendTransaction returned empty hash");
    }
    tracing::info!(hash = %hash, "transaction_submitted");
    Ok(hash)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxConfirmStatus {
    Success,
    Failed { detail: String },
    Pending,
}

/// Polls transaction status once.
#[tracing::instrument(name = "confirm_tx", level = "info", skip_all, fields(correlation_id = %types::correlation_id_or_new(), hash = %hash))]
pub async fn confirm_tx(rpc: &Client, hash: &str) -> Result<TxConfirmStatus> {
    let status = rpc
        .get_transaction(hash)
        .await
        .with_context(|| format!("getTransaction failed for {hash}"))?;
    match status.status.as_str() {
        "SUCCESS" => {
            tracing::info!(hash = %hash, status = "SUCCESS", "transaction_confirmed");
            Ok(TxConfirmStatus::Success)
        }
        "FAILED" => {
            let detail = status
                .result_xdr
                .map(|xdr| format!(" (resultXdr: {xdr})"))
                .unwrap_or_default();
            tracing::warn!(hash = %hash, status = "FAILED", detail_len = detail.len(), "transaction_failed");
            Ok(TxConfirmStatus::Failed { detail })
        }
        _ => {
            tracing::debug!(hash = %hash, "transaction_pending");
            Ok(TxConfirmStatus::Pending)
        }
    }
}
