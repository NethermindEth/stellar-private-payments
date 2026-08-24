//! Demonstrates a private transfer from the pool to a recipient.
//!
//! This example builds real zero-knowledge proofs and submits transactions to
//! the Stellar testnet. The wallet must already hold spendable notes in the
//! selected pool; run the `deposit` example first if it does not.
//!
//! Run:
//!   cargo run --release --example transfer
//!
//! Required env vars:
//!   STELLAR_SECRET_KEY    Stellar secret key for the sending account.
//!
//!   SPP_RECIPIENT_ADDRESS Registered Stellar address (registry lookup), OR
//!
//!   SPP_RECIPIENT_NOTE_KEY + SPP_RECIPIENT_ENCRYPTION_KEY
//!                         Direct 0x-prefixed 32-byte public keys.
//!
//! Optional env vars:
//!   SPP_RPC_URL               default: https://soroban-testnet.stellar.org
//!
//!   SPP_WALLET_PATH           default: ./spp-example-wallet.sqlite
//!
//!   SPP_DEPLOYMENT_JSON       default: deployments/testnet/deployments.json
//!
//!   SPP_POOL_CONTRACT_ID      default: first enabled pool in deployment config
//!
//!   SPP_CIRCUIT_KEYS_DIR      default: deployments/testnet/circuit_keys
//!
//!   SPP_CIRCUIT_ARTIFACTS_DIR default:
//! target/circuits-artifacts
//!
//!   SPP_AMOUNT_STROOPS        default: 10000000 (1 XLM)

mod common;

use stellar_private_payments::{
    Error, TransferRecipient,
    types::{EncryptionPublicKey, NotePublicKey},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let (client, account, pool, _config, pool_config) = match common::init_transact_session() {
        Ok(session) => session,
        Err(e) if e.contains("make circuits") => {
            eprintln!("Skipping: {e}");
            std::process::exit(0);
        }
        Err(e) => return Err(e.into()),
    };
    let amount = common::amount()?;

    println!("Pool:      {}", pool_config.pool_contract_id);
    println!("Asset:     {}", pool_config.token_label());
    println!("Amount:    {} stroops", u128::from(amount));
    println!("Address:   {}", account.user_address());
    println!();

    println!("Loading spendable notes...");
    let notes = pool.spendable_notes().map_err(|e| {
        if common::is_retention_gap_error(&e) {
            common::skip_on_retention_gap(&e);
        }
        Box::new(e) as Box<dyn std::error::Error>
    })?;
    if notes.is_empty() {
        println!("Skipping: no spendable notes in the selected pool.");
        println!("Deposit first, then re-run this example (see deposit.rs).");
        std::process::exit(0);
    }
    let total: u128 = notes
        .iter()
        .map(|n| u128::from(n.amount))
        .fold(0u128, u128::saturating_add);
    println!(
        "Available: {} note(s) totaling {} stroops",
        notes.len(),
        total
    );
    if u128::from(amount) > total {
        println!(
            "Skipping: requested amount ({} stroops) exceeds available notes ({} stroops).",
            u128::from(amount),
            total
        );
        println!("Lower SPP_AMOUNT_STROOPS or deposit more, then re-run this example.");
        std::process::exit(0);
    }
    println!();

    let recipient = resolve_recipient(&client)?;
    println!("Recipient: {recipient:?}");

    println!();
    println!("Estimating transaction count...");
    // Intentional duplicate work: `pool.transfer` below re-fetches spendable
    // notes and re-runs `prepare_transfer` internally. We build the plan here
    // only to show the expected tx count before committing to the real submit.
    let plan = pool.prepare_transfer(&notes, recipient.clone(), amount)?;
    println!("Expected on-chain transactions: {}", plan.tx_count());

    println!();
    println!("Submitting transfer (proving may take a while)...");
    match pool.transfer(recipient, amount) {
        Ok(results) => {
            println!("Transfer submitted and confirmed.");
            for (i, result) in results.iter().enumerate() {
                println!(
                    "  tx {} of {}: {}",
                    i.saturating_add(1),
                    results.len(),
                    result.tx_hash
                );
                println!(
                    "    explorer: https://stellar.expert/explorer/testnet/tx/{}",
                    result.tx_hash
                );
            }
        }
        Err(e) if common::is_retention_gap_error(&e) => common::skip_on_retention_gap(&e),
        Err(Error::PlanExecution(e)) => {
            print_plan_execution_error(&e);
        }
        Err(e) => return Err(Box::new(e)),
    }

    Ok(())
}

fn resolve_recipient(
    client: &stellar_private_payments::blocking::Client,
) -> Result<TransferRecipient, Box<dyn std::error::Error>> {
    let address = common::env_or("SPP_RECIPIENT_ADDRESS", "");
    if !address.is_empty() {
        println!("Resolving recipient registry keys for {address}...");
        let lookup = client.recipient_lookup(&address)?;
        match lookup.entry {
            Some(entry) => {
                println!("  note key:        {:?}", entry.note_key);
                println!("  encryption key:  {:?}", entry.encryption_key);
            }
            None => {
                eprintln!(
                    "Skipping: {address} is not yet registered in the on-chain key registry."
                );
                eprintln!(
                    "Onboard the recipient with registration enabled (e.g. `spp onboard --register`, or SPP_REGISTER=1 cargo run --release --example account_pool), then retry."
                );
                std::process::exit(0);
            }
        }
        return Ok(TransferRecipient::from(address));
    }

    let note_key = common::env_or("SPP_RECIPIENT_NOTE_KEY", "");
    let enc_key = common::env_or("SPP_RECIPIENT_ENCRYPTION_KEY", "");
    if !note_key.is_empty() && !enc_key.is_empty() {
        let note = NotePublicKey::parse(&note_key)
            .map_err(|e| format!("invalid SPP_RECIPIENT_NOTE_KEY: {e}"))?;
        let enc = EncryptionPublicKey::parse(&enc_key)
            .map_err(|e| format!("invalid SPP_RECIPIENT_ENCRYPTION_KEY: {e}"))?;
        return Ok(TransferRecipient::keys(note, enc));
    }

    eprintln!("Skipping: a recipient is required.");
    eprintln!(
        "Set SPP_RECIPIENT_ADDRESS to a registered Stellar address, or set both SPP_RECIPIENT_NOTE_KEY and SPP_RECIPIENT_ENCRYPTION_KEY."
    );
    std::process::exit(0);
}

fn print_plan_execution_error(e: &stellar_private_payments::PlanExecutionError) {
    eprintln!();
    eprintln!(
        "Plan stopped after {} transaction(s) were already confirmed on-chain:",
        e.completed.len()
    );
    for result in &e.completed {
        eprintln!("  - {}", result.tx_hash);
    }
    eprintln!();
    eprintln!("Failure reason: {}", e.cause());
    eprintln!("Run `cargo run --example sync` to catch up, then retry this example.");
}
