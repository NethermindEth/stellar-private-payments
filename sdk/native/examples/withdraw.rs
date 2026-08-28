//! Demonstrates withdrawing from the pool to a public Stellar address.
//!
//! This example builds real zero-knowledge proofs and submits transactions to
//! the Stellar testnet. Withdrawal moves funds from the private pool back to a
//! public address, which is a privacy boundary. The wallet must already hold
//! spendable notes in the selected pool.
//!
//! Run:
//!   cargo run --release --example withdraw
//!
//! Required env var:
//!   STELLAR_SECRET_KEY   Stellar secret key for the sending account.
//!
//! Optional env vars:
//!   SPP_RECIPIENT_ADDRESS     default: the wallet's own Stellar address
//!                             (self-withdrawal, the safe demo path).
//!
//!   SPP_RPC_URL               default: https://soroban-testnet.stellar.org
//!
//!   SPP_WALLET_PATH           default: ./spp-example-wallet.sqlite
//!
//!   SPP_DEPLOYMENT_JSON       default: deployments/testnet/deployments.json
//!
//!   SPP_POOL_CONTRACT_ID      default: first enabled pool in deployment config
//!
//!   SPP_AMOUNT_STROOPS        default: 10000000 (1 XLM)

mod common;

use stellar_private_payments::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let (_client, account, pool, _config, pool_config) = match common::init_transact_session() {
        Ok(session) => session,
        Err(e) if e.contains("circuit artifacts") => {
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

    let recipient = common::env_or("SPP_RECIPIENT_ADDRESS", account.user_address().as_str());
    println!("Recipient: {recipient}");
    if recipient == account.user_address().as_str() {
        println!("(Using self-withdrawal; funds will return to the wallet's public address.)");
    }

    println!();
    println!("Estimating transaction count...");
    // Intentional duplicate work: `pool.withdraw` below re-fetches spendable
    // notes and re-runs `prepare_withdraw` internally. We build the plan here
    // only to show the expected tx count before committing to the real submit.
    let plan = pool.prepare_withdraw(&notes, amount, &recipient)?;
    println!("Expected on-chain transactions: {}", plan.tx_count());

    println!();
    println!("Submitting withdrawal (proving may take a while)...");
    match pool.withdraw(amount, &recipient) {
        Ok(results) => {
            println!("Withdrawal submitted and confirmed.");
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
