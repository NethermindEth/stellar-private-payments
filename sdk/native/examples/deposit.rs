//! Demonstrates a full deposit: proof generation and on-chain submission.
//!
//! This example builds a real zero-knowledge proof and submits a transaction to
//! the Stellar testnet, so it is slower than the read-only examples. Make sure
//! the wallet is funded. Circuit artifacts download into
//! `target/circuits-artifacts` on first run.
//!
//! Run:
//!   cargo run --release --example deposit
//!
//! Required env vars:
//!   STELLAR_SECRET_KEY  Stellar secret key for the funded testnet account.
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

    common::require_funded_for_pool(&account, &pool_config, amount);

    println!("Pool:      {}", pool_config.pool_contract_id);
    println!("Asset:     {}", pool_config.token_label());
    println!("Amount:    {} stroops", u128::from(amount));
    println!("Address:   {}", account.user_address());
    println!();

    println!("Submitting deposit (proving may take a while)...");
    match pool.deposit(amount) {
        Ok(result) => {
            print_result(&result, pool_config.pool_contract_id.as_str());
        }
        Err(e) if common::is_retention_gap_error(&e) => common::skip_on_retention_gap(&e),
        Err(Error::PlanExecution(e)) => {
            print_plan_execution_error(&e);
        }
        Err(e) => return Err(Box::new(e)),
    }

    Ok(())
}

fn print_result(result: &stellar_private_payments::types::TransactionResult, pool_id: &str) {
    println!("Deposit submitted and confirmed.");
    println!("  tx hash:   {}", result.tx_hash);
    println!(
        "  explorer:  https://stellar.expert/explorer/testnet/tx/{}",
        result.tx_hash
    );
    println!();
    println!(
        "Check the updated pool balance with: SPP_POOL_CONTRACT_ID={pool_id} cargo run --release --example account_pool"
    );
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
