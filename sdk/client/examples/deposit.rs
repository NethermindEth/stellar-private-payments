//! Demonstrates a full deposit: proof generation and on-chain submission.
//!
//! This example builds a real zero-knowledge proof and submits a transaction to
//! the Stellar testnet, so it is slower than the read-only examples. Make sure
//! the wallet account is funded with the pool asset (XLM for the default pool)
//! and that circuit artifacts have been generated.
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
//!   SPP_CIRCUIT_KEYS_DIR      default: deployments/testnet/circuit_keys
//!
//!   SPP_CIRCUIT_ARTIFACTS_DIR default:
//! target/circuits-artifacts/{debug|release}
//!
//!   SPP_AMOUNT_STROOPS        default: 10000000 (1 XLM)
//!
//!   SPP_VERBOSE_PLAN          default: unset; set to "1" for step-by-step logs

mod common;

use stellar_private_payments_sdk::{Error, PreparedTransaction};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let (client, account, pool, _config, pool_config) = match common::init_transact_session() {
        Ok(session) => session,
        Err(e) if e.contains("cargo build -p circuits") => {
            eprintln!("Skipping: {e}");
            std::process::exit(0);
        }
        Err(e) => return Err(e.into()),
    };
    let amount = common::amount()?;

    common::require_funded_for_pool(&client, &account, &pool_config, amount)?;

    println!("Pool:      {}", pool_config.pool_contract_id);
    println!("Asset:     {}", pool_config.token_label());
    println!("Amount:    {} stroops", u128::from(amount));
    println!("Address:   {}", account.user_address());
    println!();

    // Plan the deposit to report its transaction count. Deliberately *not*
    // `pool.estimate()`: that is a spend-side estimator which loads the wallet's
    // spendable notes and asks the planner to cover `amount` from them, so on a
    // wallet with no notes it fails with `NoSpendableNotes`. A deposit is
    // input-only and needs no existing notes -- hence `prepare_deposit`, which
    // takes no wallet at all. This is the same call the web client's deposit
    // path uses.
    println!("Planning deposit...");
    let plan = pool.prepare_deposit(amount).map_err(|e| {
        if common::is_retention_gap_error(&e) {
            common::skip_on_retention_gap(&e);
        }
        Box::new(e) as Box<dyn std::error::Error>
    })?;
    println!("Expected on-chain transactions: {}", plan.tx_count());

    println!();
    if common::env_or("SPP_VERBOSE_PLAN", "") == "1" {
        println!("Running verbose deposit pipeline...");
        run_verbose_deposit(&pool, amount)?;
    } else {
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
    }

    Ok(())
}

fn run_verbose_deposit(
    pool: &stellar_private_payments_sdk::blocking::PrivatePool,
    amount: stellar_private_payments_sdk::types::NoteAmount,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut plan = pool.prepare_deposit(amount)?;
    let mut results = Vec::new();
    while !plan.is_complete() {
        let step = plan.current_tx();
        println!("Step {} of {}", step.saturating_add(1), plan.tx_count());

        println!("  proving...");
        let mut prepared: PreparedTransaction = pool.prove_next(&mut plan)?;

        println!("  simulating...");
        pool.simulate(&mut prepared)?;

        println!("  signing...");
        let signed = pool.sign(&prepared)?;

        println!("  submitting...");
        let hash = pool.submit(signed)?;
        println!("  submitted tx hash: {hash}");

        println!("  confirming...");
        let result = pool.confirm(&hash)?;
        results.push(result);
    }

    println!();
    println!(
        "Verbose pipeline complete. Confirmed transactions: {}",
        results.len()
    );
    for result in results {
        println!("  - {}", result.tx_hash);
    }

    Ok(())
}

fn print_result(result: &stellar_private_payments_sdk::types::TransactionResult, pool_id: &str) {
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

fn print_plan_execution_error(e: &stellar_private_payments_sdk::PlanExecutionError) {
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
