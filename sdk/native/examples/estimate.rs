//! Demonstrates cost/plan estimation without proving or submitting.
//!
//! This example shows how to obtain an [`Estimate`] (transaction count) from
//! [`PrivatePool::estimate`] and how to introspect a
//! [`PreparedTransactionPlan`] cursor. It uses a read-only client and only
//! plans transactions; no proof is built and nothing is submitted.
//!
//! Run:
//!   cargo run --release --example estimate
//!
//! Required env var:
//!   STELLAR_SECRET_KEY   Stellar secret key for the account (used to derive
//!                        the address and for plan reads).
//! Optional env vars:
//!   SPP_RPC_URL          default: https://soroban-testnet.stellar.org
//!   SPP_WALLET_PATH      default: ./spp-example-wallet.sqlite
//!   SPP_DEPLOYMENT_JSON  default: deployments/testnet/deployments.json
//!   SPP_POOL_CONTRACT_ID default: first enabled pool in deployment config
//!   SPP_AMOUNT_STROOPS   default: 10000000 (1 XLM)

mod common;

use stellar_private_payments::{Error, types::TransferRecipient};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let config = common::load_contract_config()?;
    let storage = common::open_storage()?;
    let client = common::build_readonly_client(storage, config.clone())?;
    let account = common::build_account(&client)?;
    common::require_onboarded(&account)?;

    let (pool, pool_config) = common::open_account_pool(&account, &config)?;
    let amount = common::amount()?;

    println!("Pool:      {}", pool_config.pool_contract_id);
    println!("Asset:     {}", pool_config.token_label());
    println!("Amount:    {} stroops", u128::from(amount));
    println!();

    println!("Estimating transaction count...");
    match pool.estimate(amount) {
        Ok(estimate) => {
            println!(
                "Estimated number of on-chain transactions: {}",
                estimate.tx_count
            );
        }
        Err(Error::Plan(e)) => {
            println!("Estimate unavailable: {e}");
            println!("(This usually means the wallet has no spendable notes yet.)");
        }
        Err(e) if common::is_retention_gap_error(&e) => common::skip_on_retention_gap(&e),
        Err(e) => return Err(Box::new(e)),
    }

    println!();
    println!("Deposit plan introspection (always a single transaction):");
    let deposit_plan = pool.prepare_deposit(amount)?;
    print_plan_cursor(&deposit_plan);

    let notes = pool.spendable_notes().map_err(|e| {
        if common::is_retention_gap_error(&e) {
            common::skip_on_retention_gap(&e);
        }
        Box::new(e) as Box<dyn std::error::Error>
    })?;
    println!();
    if notes.is_empty() {
        println!("No spendable notes available; skipping transfer-plan demo.");
        println!("Deposit first, then re-run this example to see a multi-tx spend plan.");
    } else {
        let total: u128 = notes
            .iter()
            .map(|n| u128::from(n.amount))
            .fold(0u128, u128::saturating_add);
        println!(
            "Spend plan introspection ({} spendable note(s) totaling {} stroops):",
            notes.len(),
            total
        );
        if u128::from(amount) > total {
            println!(
                "Skipping: requested amount ({} stroops) exceeds available notes ({} stroops).",
                u128::from(amount),
                total
            );
            println!("Lower SPP_AMOUNT_STROOPS or deposit more to see a spend plan.");
        } else {
            let recipient = TransferRecipient::from(account.user_address().as_str());
            let transfer_plan = pool.prepare_transfer(&notes, recipient, amount)?;
            print_plan_cursor(&transfer_plan);
        }
    }

    println!();
    println!("No transactions were built, signed, or submitted.");

    Ok(())
}

fn print_plan_cursor(plan: &stellar_private_payments::plan::PreparedTransactionPlan) {
    println!("  total transactions: {}", plan.tx_count());
    println!("  current transaction: {}", plan.current_tx());
    println!("  is complete: {}", plan.is_complete());
}
