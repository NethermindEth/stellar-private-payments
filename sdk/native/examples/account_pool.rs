//! Demonstrates account identity and pool-state reads.
//!
//! This example is read-only by default. It prints the account's Stellar
//! address, registration status, derived privacy public keys, portfolio, and
//! notes, then opens the selected pool and prints its balance and notes.
//!
//! Run:
//!   cargo run --release --example account_pool
//!
//! Required env var:
//!   STELLAR_SECRET_KEY   Stellar secret key for the account.
//! Optional env vars:
//!   SPP_RPC_URL          default: https://soroban-testnet.stellar.org
//!   SPP_WALLET_PATH      default: ./spp-example-wallet.sqlite
//!   SPP_DEPLOYMENT_JSON  default: deployments/testnet/deployments.json
//!   SPP_POOL_CONTRACT_ID default: first enabled pool in deployment config
//!   SPP_REGISTER         default: unset; set to "1" to actually call
//!                        register_public_keys (this performs an on-chain
//!                        write and costs a small amount of XLM).

mod common;

use stellar_private_payments::types::PortfolioBalance;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let config = common::load_contract_config()?;
    let storage = common::open_storage()?;
    let client = common::build_readonly_client(storage, config.clone())?;
    let account = common::build_account(&client)?;
    common::require_onboarded(&account)?;

    println!("Account: {}", account.user_address());
    println!();

    println!("Syncing account state...");
    account.sync().map_err(|e| {
        if common::is_retention_gap_error(&e) {
            common::skip_on_retention_gap(&e);
        }
        Box::new(e) as Box<dyn std::error::Error>
    })?;

    let registered = account.is_registered()?;
    println!("Registered on-chain: {registered}");

    if registered {
        println!("Privacy public keys are already published.");
    } else {
        println!("Privacy public keys are NOT yet published on-chain.");
        println!(
            "Set SPP_REGISTER=1 to call register_public_keys (this performs an on-chain write)."
        );
    }

    println!();
    println!("Stored privacy public keys:");
    let (note_key, enc_key) = account.user_public_keys()?;
    println!("  note key:        {note_key:?}");
    println!("  encryption key:  {enc_key:?}");

    println!();
    println!("Portfolio across enabled pools:");
    let portfolio: Vec<PortfolioBalance> = account.portfolio()?;
    if portfolio.is_empty() {
        println!("  (no balances)");
    } else {
        for entry in portfolio {
            println!(
                "  {} | {} | amount={} | notes={}",
                entry.pool_contract_id, entry.token_label, entry.amount, entry.note_count
            );
        }
    }

    println!();
    println!("User notes (up to 10):");
    let notes = account.user_notes(10)?;
    if notes.is_empty() {
        println!("  (no notes)");
    } else {
        for note in notes {
            println!(
                "  {} | amount={} | spent={} | pool={}",
                note.id, note.amount, note.spent, note.pool_contract_id
            );
        }
    }

    println!();
    println!("Enabled pools:");
    for pool in config.enabled_pools() {
        println!(
            "  {} | asset={} | policy={:?}",
            pool.pool_contract_id,
            pool.token_label(),
            pool.policy_flags
        );
    }

    let (pool, pool_config) = common::open_account_pool(&account, &config)?;
    println!();
    println!("Selected pool: {}", pool_config.pool_contract_id);
    println!("Pool config: {pool_config:?}");

    println!();
    println!("Pool balance: {}", pool.balance()?);

    println!();
    println!("Pool notes:");
    let pool_notes = pool.notes()?;
    if pool_notes.is_empty() {
        println!("  (no notes)");
    } else {
        println!("  total: {}", pool_notes.len());
        for note in pool_notes {
            println!(
                "  {} | amount={} | spent={}",
                note.id, note.amount, note.spent
            );
        }
    }

    println!();
    println!("Spendable pool notes:");
    let spendable = pool.spendable_notes()?;
    if spendable.is_empty() {
        println!("  (none)");
    } else {
        let total: u128 = spendable
            .iter()
            .map(|n| u128::from(n.amount))
            .fold(0u128, |acc, v| acc.saturating_add(v));
        println!("  count: {} | total amount: {}", spendable.len(), total);
    }

    if !registered && common::env_or("SPP_REGISTER", "") == "1" {
        println!();
        println!("SPP_REGISTER=1: publishing privacy public keys on-chain...");
        let result = account.register_public_keys(None, None)?;
        println!("Registration tx hash: {}", result.tx_hash);
    }

    Ok(())
}
