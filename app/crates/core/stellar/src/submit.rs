//! Submit signed Soroban transactions to RPC.

use anyhow::{Context, Result, bail};
use stellar_xdr::curr::TransactionEnvelope;

use crate::rpc::Client;

const CONFIRM_POLL_ATTEMPTS: u32 = 30;
const CONFIRM_POLL_INTERVAL_SECS: u64 = 1;

/// Sends a signed transaction and polls until success or failure.
pub async fn submit_and_confirm(signed: &TransactionEnvelope, rpc: &Client) -> Result<String> {
    let send = rpc
        .send_transaction(signed)
        .await
        .context("sendTransaction failed")?;
    let hash = send.hash;
    if hash.is_empty() {
        bail!("sendTransaction returned empty hash");
    }

    for attempt in 1..=CONFIRM_POLL_ATTEMPTS {
        confirm_sleep().await;
        let status = rpc
            .get_transaction(&hash)
            .await
            .with_context(|| format!("getTransaction failed for {hash}"))?;
        match status.status.as_str() {
            "SUCCESS" => return Ok(hash),
            "FAILED" => {
                let detail = status
                    .result_xdr
                    .map(|xdr| format!(" (resultXdr: {xdr})"))
                    .unwrap_or_default();
                bail!("transaction failed{detail}");
            }
            _ if attempt == CONFIRM_POLL_ATTEMPTS => {
                bail!("transaction confirmation timed out after 30s (hash: {hash})");
            }
            _ => {}
        }
    }

    bail!("transaction confirmation failed (hash: {hash})");
}

async fn confirm_sleep() {
    #[cfg(target_arch = "wasm32")]
    {
        gloo_timers::future::TimeoutFuture::new(
            u32::try_from(CONFIRM_POLL_INTERVAL_SECS.saturating_mul(1_000)).unwrap_or(u32::MAX),
        )
        .await;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::sleep(std::time::Duration::from_secs(CONFIRM_POLL_INTERVAL_SECS));
    }
}
