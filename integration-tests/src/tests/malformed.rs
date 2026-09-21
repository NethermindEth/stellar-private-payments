use anyhow::Result;
use stellar_private_payments::types::SignedTransaction;

use super::support::{deploy_default, session};

#[tokio::test]
async fn confirm_unknown_hash() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let confirmed = pool
        .confirm("0000000000000000000000000000000000000000000000000000000000000000")
        .await;
    assert!(
        confirmed.is_err(),
        "confirming a hash that was never submitted must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn submit_malformed_signed_tx() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let submitted = pool
        .submit(SignedTransaction {
            signed_xdr: "not valid base64 xdr".to_string(),
        })
        .await;
    assert!(
        submitted.is_err(),
        "submitting a malformed signed transaction must be rejected"
    );

    Ok(())
}
