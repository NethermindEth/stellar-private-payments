//! Reports a transaction's simulated on-chain cost — footprint, resources,
//! fees — without signing or submitting it.

use anyhow::{Context, Result, bail};
use serde::Serialize;
use stellar_private_payments::chain::{Limits, ReadXdr, TransactionEnvelope};
use stellar_xdr::{LedgerKey, ScAddress, ScVal, TransactionExt};

use crate::{cmd::pool::open_pool, config::CliConfig, output, session::parse_amount};

#[derive(Debug, Clone, Serialize)]
pub struct CostReport {
    pub pool_contract_id: String,
    pub amount_stroops: u128,
    pub read_only_entries: Vec<String>,
    pub read_write_entries: Vec<String>,
    pub instructions: u32,
    pub disk_read_bytes: u32,
    pub write_bytes: u32,
    pub resource_fee_stroops: i64,
    pub inclusion_fee_stroops: i64,
    pub total_fee_stroops: i64,
}

/// Prove and simulate a deposit, without signing or submitting it, and
/// report its cost.
pub fn deposit(config: &CliConfig, pool: &str, amount: &str, json: bool) -> Result<()> {
    let pool_session = open_pool(config, pool)?;
    let amount = parse_amount(amount)?;

    let mut plan = pool_session
        .prepare_deposit(amount)
        .map_err(|e| anyhow::anyhow!("prepare deposit: {e:#}"))?;
    let mut prepared = pool_session
        .prove_next(&mut plan)
        .map_err(|e| anyhow::anyhow!("prove deposit: {e:#}"))?;
    pool_session
        .simulate(&mut prepared)
        .map_err(|e| anyhow::anyhow!("simulate deposit: {e:#}"))?;

    let report = report_from_tx_xdr(pool, u128::from(amount), &prepared.soroban_tx.tx_xdr)?;
    print_report(&report, json)
}

fn report_from_tx_xdr(pool: &str, amount_stroops: u128, tx_xdr: &str) -> Result<CostReport> {
    let envelope = TransactionEnvelope::from_xdr_base64(tx_xdr, Limits::none())
        .context("decode simulated transaction xdr")?;
    let TransactionEnvelope::Tx(v1) = envelope else {
        bail!("expected a v1 transaction envelope");
    };
    let tx = v1.tx;
    let TransactionExt::V1(soroban_data) = &tx.ext else {
        bail!("expected simulation to attach Soroban transaction data");
    };
    let resources = &soroban_data.resources;
    let inclusion_fee_stroops = i64::from(tx.fee).saturating_sub(soroban_data.resource_fee);

    Ok(CostReport {
        pool_contract_id: pool.to_string(),
        amount_stroops,
        read_only_entries: resources
            .footprint
            .read_only
            .iter()
            .map(describe_ledger_key)
            .collect(),
        read_write_entries: resources
            .footprint
            .read_write
            .iter()
            .map(describe_ledger_key)
            .collect(),
        instructions: resources.instructions,
        disk_read_bytes: resources.disk_read_bytes,
        write_bytes: resources.write_bytes,
        resource_fee_stroops: soroban_data.resource_fee,
        inclusion_fee_stroops,
        total_fee_stroops: i64::from(tx.fee),
    })
}

fn print_report(report: &CostReport, json: bool) -> Result<()> {
    if json {
        return output::emit(report, true);
    }
    output::print_section("Simulated deposit cost");
    output::print_kv("pool", &report.pool_contract_id);
    output::print_kv("amount_stroops", report.amount_stroops);
    output::print_kv("read_only_entries", report.read_only_entries.len());
    for entry in &report.read_only_entries {
        println!("    - {entry}");
    }
    output::print_kv("read_write_entries", report.read_write_entries.len());
    for entry in &report.read_write_entries {
        println!("    - {entry}");
    }
    output::print_kv("instructions", report.instructions);
    output::print_kv("disk_read_bytes", report.disk_read_bytes);
    output::print_kv("write_bytes", report.write_bytes);
    output::print_kv("resource_fee_stroops", report.resource_fee_stroops);
    output::print_kv("inclusion_fee_stroops", report.inclusion_fee_stroops);
    output::print_kv("total_fee_stroops", report.total_fee_stroops);
    Ok(())
}

/// Short label for a footprint entry: the contract and storage key for
/// contract data, or just the ledger-entry kind otherwise.
fn describe_ledger_key(key: &LedgerKey) -> String {
    match key {
        LedgerKey::ContractData(data) => {
            let contract = match &data.contract {
                ScAddress::Contract(id) => stellar_strkey::Contract(id.0.0)
                    .to_string()
                    .as_str()
                    .to_string(),
                _ => "<non-contract address>".to_string(),
            };
            format!("{contract} / {}", describe_storage_key(&data.key))
        }
        LedgerKey::ContractCode(_) => "contract code".to_string(),
        LedgerKey::Account(_) => "classic account".to_string(),
        LedgerKey::Trustline(_) => "trustline".to_string(),
        LedgerKey::Ttl(_) => "ttl".to_string(),
        _ => "other".to_string(),
    }
}

fn describe_storage_key(key: &ScVal) -> String {
    match key {
        ScVal::LedgerKeyContractInstance => "instance".to_string(),
        ScVal::Vec(Some(items)) => items
            .iter()
            .map(describe_scval_component)
            .collect::<Vec<_>>()
            .join("::"),
        other => format!("{other:?}"),
    }
}

fn describe_scval_component(val: &ScVal) -> String {
    match val {
        ScVal::Symbol(name) => name.to_utf8_string_lossy(),
        ScVal::U32(n) => n.to_string(),
        other => format!("{other:?}"),
    }
}
