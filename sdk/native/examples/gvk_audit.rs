//! Demonstrates GVK admin audit: generate/load the authority key, sync, decrypt
//! pool events.
//!
//! No wallet secret is required. The example stores the admin scalar in the
//! local wallet database under the `gvk_authority` app setting.
//!
//! Run:
//!   cargo run --release --example gvk_audit
//!
//! With no GVK pool in deployment config, the example still generates (or
//! loads) the authority key and prints the public key JSON for `deploy.sh
//! --gvk-authority-pubkey`.
//!
//! Env vars:
//!   SPP_RPC_URL              default: https://soroban-testnet.stellar.org
//!   SPP_BOOTNODE_URL         default: https://bootnode.dev-nethermind.xyz
//!   SPP_WALLET_PATH          default: ./spp-example-wallet.sqlite
//!   SPP_DEPLOYMENT_JSON      default: deployments/testnet/deployments.json
//!   SPP_POOL_CONTRACT_ID     optional; must be a pool-gvk deployment when set
//!
//! Each note is printed on one line (amount, commitment, pk). Traceable inputs
//! traceable pools, tx kind (deposit / transfer / withdraw) is shown when
//! inputs are visible; view-only pools omit it.

mod common;

use std::collections::HashMap;

use stellar_private_payments::{
    GvkAudit, GvkAuditedNote, GvkMode, GvkTxAudit, LocalStorage, Storage, types::Field,
};

const AUDIT_LIMIT: u32 = 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    common::init_tracing()?;

    let config = common::load_contract_config()?;
    let wallet_path = common::env_or("SPP_WALLET_PATH", common::default_wallet_path());
    let storage = common::open_storage()?;
    let created = storage.get_gvk_authority_setting()?.is_none();
    let authority = common::load_or_create_gvk_authority(&storage)?;
    let pubkey_json = serde_json::to_string(&authority.public_key)
        .map_err(|e| format!("serialize GVK authority public key: {e}"))?;

    println!("Network:  {}", config.network);
    println!("Wallet:   {wallet_path}");
    if created {
        println!("GVK authority key generated and saved to app setting `gvk_authority`.");
    } else {
        println!("Loaded GVK authority key from app setting `gvk_authority`.");
    }
    println!("Public x: {}", authority.public_key.x);
    println!("Public y: {}", authority.public_key.y);
    println!();
    println!("Deploy with:");
    println!("  --gvk-authority-pubkey '{pubkey_json}'");
    println!("  # or save the JSON above and pass --gvk-authority-pubkey-file PATH");

    let pool = match common::select_gvk_pool(&config) {
        Ok(pool) => pool,
        Err(reason) => {
            println!();
            println!("No audit run: {reason}.");
            println!("Deploy a pool-gvk pool with the public key above, then re-run.");
            return Ok(());
        }
    };

    common::validate_gvk_authority_for_pool(&authority, pool)?;

    let pool_contract_id = pool.pool_contract_id.clone();
    let pool_gvk_mode = pool.gvk_mode;

    println!();
    println!("Pool:     {pool_contract_id} ({pool_gvk_mode:?})");

    let client = common::build_readonly_client(storage, config)?;
    println!();
    println!("Syncing local storage...");
    match client.sync() {
        Ok(()) => println!("Sync complete."),
        Err(e) if common::is_retention_gap_error(&e) => {
            common::skip_on_retention_gap(&e);
        }
        Err(e) => return Err(Box::new(e)),
    }

    let d_priv = authority.private_key;

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(run_audit(
        client
            .storage()
            .fork()
            .map_err(|e| format!("fork storage: {e}"))?,
        &pool_contract_id,
        d_priv,
        pool_gvk_mode,
        AUDIT_LIMIT,
    ))?;

    Ok(())
}

async fn run_audit(
    storage: LocalStorage,
    pool_contract_id: &str,
    d_priv: stellar_private_payments::types::Field,
    gvk_mode: GvkMode,
    limit: u32,
) -> Result<(), String> {
    let mut audit = GvkAudit::new(storage, pool_contract_id, d_priv);
    let mut count = 0u32;
    let mut origins: HashMap<Field, NoteOrigin> = HashMap::new();

    println!();
    println!("Auditing pool transacts (limit {limit})...");
    while count < limit {
        let Some(tx) = audit
            .next_tx()
            .await
            .map_err(|e| format!("audit next tx: {e}"))?
        else {
            break;
        };

        count = count.saturating_add(1);
        let prefix = (gvk_mode == GvkMode::Traceable)
            .then(|| classify_tx(&tx))
            .map(|kind| format!("{kind} — "))
            .unwrap_or_default();
        println!(
            "  tx {count}: {prefix}ledger {} — {} outputs, {} inputs, {} nullifiers",
            tx.ledger,
            tx.outputs.len(),
            tx.inputs.len(),
            tx.nullifiers.len(),
        );
        for (i, note) in tx.outputs.iter().enumerate() {
            println!("    output[{i}]: {}", format_note_line(note));
            origins.insert(
                note.commitment,
                NoteOrigin {
                    tx: count,
                    ledger: tx.ledger,
                    output_index: i,
                },
            );
        }
        for (i, note) in tx.inputs.iter().enumerate() {
            let nullifier = tx
                .nullifiers
                .get(i)
                .map(|n| format!("nullifier={}", truncate_hex(n)))
                .unwrap_or_else(|| "nullifier=—".to_string());
            println!(
                "    input[{i}]: {} | {} | {}",
                format_note_line(note),
                nullifier,
                format_spent_from(&origins, note.commitment),
            );
        }
    }

    if count == 0 {
        println!("  (no audited transacts yet — pool may have no activity)");
    } else if count == limit {
        println!("  (limit reached)");
    }

    Ok(())
}

struct NoteOrigin {
    tx: u32,
    ledger: u32,
    output_index: usize,
}

fn sum_amounts(notes: &[GvkAuditedNote]) -> u128 {
    notes.iter().map(|n| u128::from(n.note.amount())).sum()
}

/// Deposit: no real inputs (dummy slots on deposit). Transfer: inputs ==
/// outputs. Withdraw: inputs > outputs (public exit; zero-amount outputs are
/// omitted).
fn classify_tx(tx: &GvkTxAudit) -> &'static str {
    let input_sum = sum_amounts(&tx.inputs);
    let output_sum = sum_amounts(&tx.outputs);

    if tx.inputs.is_empty() {
        if output_sum > 0 {
            return "deposit";
        }
        if !tx.nullifiers.is_empty() {
            return "withdraw";
        }
        return "transfer";
    }

    if input_sum > output_sum {
        "withdraw"
    } else {
        "transfer"
    }
}

fn truncate_hex(field: &Field) -> String {
    let s = field.to_string();
    s.chars().take(9).collect()
}

fn format_note_line(note: &GvkAuditedNote) -> String {
    format!(
        "pk={} amount={} stroops commitment={}",
        truncate_hex(&note.note.pk),
        u128::from(note.note.amount()),
        truncate_hex(&note.commitment),
    )
}

fn format_spent_from(origins: &HashMap<Field, NoteOrigin>, commitment: Field) -> String {
    match origins.get(&commitment) {
        Some(origin) => format!(
            "from=tx{} ledger{} output[{}]",
            origin.tx, origin.ledger, origin.output_index
        ),
        None => "from=unknown".to_string(),
    }
}
