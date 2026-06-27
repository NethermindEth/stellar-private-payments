use anyhow::Result;
use serde::Serialize;
use stellar_private_payments_sdk::types::{TransactionResult, UserNoteSummary};

use crate::{
    config::CliConfig,
    output,
    session::{PoolSession, TransferRecipientCmd, parse_amount, resolve_transfer_recipient_cmd},
};

pub fn balance(
    config: &CliConfig,
    json: bool,
    circuits_dir: Option<&std::path::Path>,
) -> Result<()> {
    let session = PoolSession::open(config, circuits_dir)?;
    let balance = session
        .pool()
        .balance()
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    #[derive(Serialize)]
    struct BalanceOut {
        pool: String,
        account: String,
        balance_stroops: String,
    }

    let payload = BalanceOut {
        pool: config.require_pool()?.to_string(),
        account: config.require_wallet()?.address.clone(),
        balance_stroops: balance.to_string(),
    };

    if json {
        output::emit(&payload, true)?;
        return Ok(());
    }

    output::print_section("Pool balance");
    output::print_kv("pool", &payload.pool);
    output::print_kv("account", &payload.account);
    output::print_kv("balance_stroops", &payload.balance_stroops);
    Ok(())
}

pub fn notes(config: &CliConfig, json: bool, circuits_dir: Option<&std::path::Path>) -> Result<()> {
    let session = PoolSession::open(config, circuits_dir)?;
    let notes = session.pool().notes().map_err(|e| anyhow::anyhow!("{e}"))?;

    if json {
        output::emit(&notes, true)?;
        return Ok(());
    }

    print_notes(&notes);
    Ok(())
}

pub fn deposit(
    config: &CliConfig,
    amount: &str,
    json: bool,
    circuits_dir: Option<&std::path::Path>,
) -> Result<()> {
    let session = PoolSession::open(config, circuits_dir)?;
    let amount = parse_amount(amount)?;
    let result = session
        .pool()
        .deposit(amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    print_tx_result("Deposit submitted", &result, json)
}

pub fn transfer(
    config: &CliConfig,
    amount: &str,
    recipient: &TransferRecipientCmd,
    json: bool,
    circuits_dir: Option<&std::path::Path>,
) -> Result<()> {
    let session = PoolSession::open(config, circuits_dir)?;
    let recipient = resolve_transfer_recipient_cmd(config, recipient)?;
    let amount = parse_amount(amount)?;
    let wallet = session
        .pool()
        .spendable_notes()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let results = session
        .pool()
        .transfer(&wallet, recipient, amount)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    print_tx_results("Transfer submitted", &results, json)
}

pub fn withdraw(
    config: &CliConfig,
    amount: &str,
    to: Option<&str>,
    json: bool,
    circuits_dir: Option<&std::path::Path>,
) -> Result<()> {
    let to = match to {
        Some(address) => address.to_string(),
        None => config.require_wallet()?.address.clone(),
    };

    let session = PoolSession::open(config, circuits_dir)?;
    let amount = parse_amount(amount)?;
    let wallet = session
        .pool()
        .spendable_notes()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let results = session
        .pool()
        .withdraw(&wallet, amount, &to)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    print_tx_results("Withdraw submitted", &results, json)
}

fn print_notes(notes: &[UserNoteSummary]) {
    output::print_section("Pool notes");
    if notes.is_empty() {
        println!("(none)");
        return;
    }

    for note in notes {
        output::print_kv("commitment", note.id.to_string());
        output::print_kv("  amount_stroops", note.amount.to_string());
        output::print_kv("  leaf_index", note.leaf_index);
        output::print_kv("  spent", note.spent);
        output::print_kv("  created_at_ledger", note.created_at_ledger);
        println!();
    }
}

fn print_tx_result(title: &str, result: &TransactionResult, json: bool) -> Result<()> {
    print_tx_results(title, std::slice::from_ref(result), json)
}

fn print_tx_results(title: &str, results: &[TransactionResult], json: bool) -> Result<()> {
    if json {
        output::emit(results, true)?;
        return Ok(());
    }

    output::print_section(title);
    for (index, result) in results.iter().enumerate() {
        if results.len() > 1 {
            output::print_kv(&format!("tx_{index}_hash"), &result.tx_hash);
        } else {
            output::print_kv("tx_hash", &result.tx_hash);
        }
    }
    Ok(())
}
