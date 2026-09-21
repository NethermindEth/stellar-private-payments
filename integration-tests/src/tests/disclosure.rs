use anyhow::Result;
use stellar_private_payments::{
    disclosure::DisclosureRequest,
    types::{Field, NoteAmount, U256},
};

use super::support::{deploy_default, session};

const DEPOSIT_STROOPS: u128 = 10_000_000; // 1 XLM

fn disclosure_request(commitment: Field) -> DisclosureRequest {
    DisclosureRequest {
        selected_commitments: vec![commitment],
        authority_label: "integration-test-authority".to_string(),
        authority_identity_payload_hex: "0xdeadbeef".to_string(),
        purpose: "integration test".to_string(),
        context_nonce: Field::ONE,
    }
}

fn disclosure_request_with(selected_commitments: Vec<Field>) -> DisclosureRequest {
    DisclosureRequest {
        selected_commitments,
        ..disclosure_request(Field::ONE)
    }
}

#[tokio::test]
async fn disclose_basic() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;

    let wallet = pool.spendable_notes().await?;
    assert_eq!(
        wallet.len(),
        1,
        "a single deposit should produce exactly one spendable note"
    );

    let receipt = pool
        .disclose(disclosure_request(wallet[0].commitment))
        .await?
        .expect("depositor is already registered with the ASP, disclosure should proceed");

    let report = pool
        .verify_disclosure(&receipt, &receipt.circuit.vk_hash)
        .await?;
    assert!(report.proof_verified, "the disclosure proof must verify");
    assert!(
        report.context_verified,
        "the disclosure context must match the receipt"
    );
    assert!(
        report.nullifiers_unspent,
        "the disclosed note has not been spent yet"
    );
    assert!(report.spent_nullifier_indices.is_empty());

    Ok(())
}

#[tokio::test]
async fn verify_wrong_vk_hash() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;
    let wallet = pool.spendable_notes().await?;

    let receipt = pool
        .disclose(disclosure_request(wallet[0].commitment))
        .await?
        .expect("depositor is already registered with the ASP, disclosure should proceed");

    let verified = pool
        .verify_disclosure(
            &receipt,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .await;
    assert!(
        verified.is_err(),
        "verifying a receipt against the wrong vk hash must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn verify_tampered_receipt() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    pool.deposit(NoteAmount::from(DEPOSIT_STROOPS)).await?;
    let wallet = pool.spendable_notes().await?;

    let mut receipt = pool
        .disclose(disclosure_request(wallet[0].commitment))
        .await?
        .expect("depositor is already registered with the ASP, disclosure should proceed");

    receipt.public_inputs.amounts[0] -= Field::ONE;

    let report = pool
        .verify_disclosure(&receipt, &receipt.circuit.vk_hash)
        .await?;
    assert!(!report.proof_verified, "a tampered receipt must not verify");

    Ok(())
}

#[tokio::test]
async fn disclose_0_notes() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let disclosed = pool.disclose(disclosure_request_with(vec![])).await;
    assert!(
        disclosed.is_err(),
        "disclosure with zero selected commitments must be rejected"
    );

    Ok(())
}

#[tokio::test]
async fn disclose_5_notes() -> Result<()> {
    let session = session(deploy_default().await?).await?;
    let pool = session.pool()?;

    let too_many = (0..5u64).map(|i| Field(U256::from(i))).collect();
    let disclosed = pool.disclose(disclosure_request_with(too_many)).await;
    assert!(
        disclosed.is_err(),
        "disclosure with more than 4 selected commitments must be rejected"
    );

    Ok(())
}
