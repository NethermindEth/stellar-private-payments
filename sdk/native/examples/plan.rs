//! Demonstrates the lower-level `prepare_*`/[`PreparedTransactionPlan`] API:
//! plan introspection and manual step-by-step execution (prove, simulate,
//! sign, submit, confirm).
//!
//! `deposit`/`transfer`/`withdraw` cover this in one call and are the right
//! choice for almost all integrations. This example is for callers who need
//! to inspect or drive the plan themselves — e.g. a UI that shows per-step
//! progress, or a caller that wants to persist/retry individual steps.
//!
//! To produce a plan with more than one transaction, this example deposits
//! four separate notes and then withdraws all of them: a withdrawal that
//! spends several notes may need to merge them across multiple on-chain
//! transactions before the final payout.
//!
//! This example builds real zero-knowledge proofs and submits transactions to
//! the Stellar testnet, so it is slower than the read-only examples. Make
//! sure the wallet is funded. Circuit artifacts download into
//! `target/circuits-artifacts` on first run.
//!
//! Run:
//!   cargo run --release --example plan
//!
//! Required env var:
//!   STELLAR_SECRET_KEY   Stellar secret key for the funded testnet account.
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
//!   SPP_AMOUNT_STROOPS        default: 10000000 (1 XLM); amount of each of
//!                             the 4 deposited notes

mod common;

use stellar_private_payments::{
    PreparedTransaction, plan::PreparedTransactionPlan, types::NoteAmount,
};

const NOTE_COUNT: u32 = 4;

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
    let note_amount = common::amount()?;
    common::require_funded_for_pool(&account, &pool_config, total_amount(note_amount));

    println!("Pool:      {}", pool_config.pool_contract_id);
    println!("Asset:     {}", pool_config.token_label());
    println!("Address:   {}", account.user_address());
    println!();

    println!(
        "Depositing {NOTE_COUNT} notes of {} stroops each...",
        u128::from(note_amount)
    );
    for i in 1..=NOTE_COUNT {
        let result = pool.deposit(note_amount).map_err(|e| {
            if common::is_retention_gap_error(&e) {
                common::skip_on_retention_gap(&e);
            }
            Box::new(e) as Box<dyn std::error::Error>
        })?;
        println!("  note {i} of {NOTE_COUNT}: tx {}", result.tx_hash);
    }

    println!();
    println!("Loading spendable notes...");
    let notes = pool.spendable_notes()?;
    let total: u128 = notes
        .iter()
        .map(|n| u128::from(n.amount))
        .fold(0u128, u128::saturating_add);
    println!(
        "Wallet holds {} note(s) totaling {total} stroops",
        notes.len()
    );

    let recipient = common::env_or("SPP_RECIPIENT_ADDRESS", account.user_address().as_str());
    println!();
    println!("Recipient: {recipient}");
    if recipient == account.user_address().as_str() {
        println!("(Using self-withdrawal; funds will return to the wallet's public address.)");
    }

    println!();
    println!("Preparing withdrawal plan for the full balance ({total} stroops)...");
    let mut plan = pool.prepare_withdraw(&notes, NoteAmount::from(total), &recipient)?;
    print_plan_cursor(&plan);

    println!();
    println!("Executing plan step by step...");
    let mut results = Vec::new();
    while !plan.is_complete() {
        println!(
            "Step {} of {}",
            plan.current_tx().saturating_add(1),
            plan.tx_count()
        );

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
        println!("  confirmed");
        results.push(result);

        print_plan_cursor(&plan);
    }

    println!();
    println!("Plan complete. Confirmed transactions:");
    for result in &results {
        println!("  - {}", result.tx_hash);
        println!(
            "    explorer: https://stellar.expert/explorer/testnet/tx/{}",
            result.tx_hash
        );
    }

    Ok(())
}

fn total_amount(note_amount: NoteAmount) -> NoteAmount {
    NoteAmount::from(u128::from(note_amount).saturating_mul(u128::from(NOTE_COUNT)))
}

fn print_plan_cursor(plan: &PreparedTransactionPlan) {
    println!(
        "  plan: {}/{} transactions complete (is_complete: {})",
        plan.current_tx(),
        plan.tx_count(),
        plan.is_complete()
    );
}
