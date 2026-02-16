//! Stellar CLI plugin for private payments.
//!
//! Invoked as `stellar spp <command>`.

#[allow(dead_code)]
mod admin;
mod cli;
mod config;
#[allow(dead_code)]
mod crypto;
#[allow(dead_code)]
mod db;
mod display;
#[allow(dead_code)]
mod keys;
#[allow(dead_code)]
mod merkle;
mod notes;
#[allow(dead_code)]
mod proof;
#[allow(dead_code)]
mod stellar;
mod sync;
#[allow(dead_code)]
mod transaction;

use anyhow::Result;
use clap::Parser;
use cli::{AdminCommand, Cli, Commands, KeysCommand, NotesCommand};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => cmd_init(&cli),
        Commands::Sync => cmd_sync(&cli),
        Commands::Status { ref source } => cmd_status(&cli, source.as_deref()),
        Commands::Keys(ref sub) => match sub {
            KeysCommand::Derive { source } => cmd_keys_derive(&cli, source),
            KeysCommand::Show { source } => cmd_keys_show(&cli, source),
        },
        Commands::Register { ref source } => cmd_register(&cli, source),
        Commands::Deposit {
            amount,
            ref source,
        } => cmd_deposit(&cli, amount, source),
        Commands::Withdraw {
            amount,
            ref to,
            ref source,
        } => cmd_withdraw(&cli, amount, to, source),
        Commands::Transfer {
            amount,
            ref to,
            ref source,
        } => cmd_transfer(&cli, amount, to, source),
        Commands::Notes(ref sub) => match sub {
            NotesCommand::List { source } => cmd_notes_list(&cli, source),
            NotesCommand::Scan { source } => cmd_notes_scan(&cli, source),
            NotesCommand::Export { note_id } => cmd_notes_export(note_id),
            NotesCommand::Import { file } => cmd_notes_import(file),
        },
        Commands::Admin(ref sub) => match sub {
            AdminCommand::AddMember { account, source } => {
                cmd_admin_add_member(&cli, account, source)
            }
            AdminCommand::RemoveMember { account, source } => {
                cmd_admin_remove_member(&cli, account, source)
            }
            AdminCommand::UpdateAdmin {
                new_admin,
                contract,
                source,
            } => cmd_admin_update_admin(&cli, new_admin, contract.as_deref(), source),
        },
    }
}

/// Initialize deployment config and perform initial sync.
fn cmd_init(cli: &Cli) -> Result<()> {
    let cfg = config::load_or_create_config(&cli.network)?;
    println!("Deployment config for network '{}':", cli.network);
    println!("  Pool:               {}", cfg.pool);
    println!("  ASP Membership:     {}", cfg.asp_membership);
    println!("  ASP Non-Membership: {}", cfg.asp_non_membership);
    println!("  Verifier:           {}", cfg.verifier);

    let database = db::Database::open(&cli.network)?;
    database.migrate()?;
    println!("\nDatabase initialized at {}", db::db_path(&cli.network)?.display());

    println!("\nRunning initial sync...");
    sync::sync_all(&database, &cfg, &cli.network)?;
    println!("Initial sync complete.");
    Ok(())
}

/// Incremental event sync.
fn cmd_sync(cli: &Cli) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;
    sync::sync_all(&database, &cfg, &cli.network)?;
    println!("Sync complete.");
    Ok(())
}

/// Show sync status, balances, contract info.
fn cmd_status(cli: &Cli, source: Option<&str>) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;

    let pool_count = database.pool_leaf_count()?;
    let nullifier_count = database.nullifier_count()?;
    let asp_count = database.asp_leaf_count()?;

    println!("Network: {}", cli.network);
    println!("Pool contract: {}", cfg.pool);
    println!("Pool leaves: {pool_count}");
    println!("Nullifiers: {nullifier_count}");
    println!("ASP membership leaves: {asp_count}");

    if let Some(identity) = source {
        let note_privkey = keys::derive_note_private_key(identity, &cli.network)?;
        let note_pubkey = crypto::derive_public_key(&note_privkey);
        let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);

        let notes = database.list_notes(&pubkey_hex)?;
        let mut total_balance: u64 = 0;
        let mut unspent_count: u64 = 0;
        for note in &notes {
            if note.spent == 0 {
                total_balance = total_balance.saturating_add(note.amount);
                unspent_count = unspent_count.saturating_add(1);
            }
        }
        println!("\nIdentity: {identity}");
        println!("Unspent notes: {unspent_count}");
        println!("Balance: {total_balance} stroops");
    }

    Ok(())
}

/// Derive BN254/X25519 keys.
fn cmd_keys_derive(cli: &Cli, source: &str) -> Result<()> {
    let note_privkey = keys::derive_note_private_key(source, &cli.network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);

    let (enc_pub, _enc_priv) = keys::derive_encryption_keypair(source, &cli.network)?;

    println!("Keys derived for identity '{source}':");
    display::print_keys(&note_privkey, &note_pubkey, &enc_pub);
    Ok(())
}

/// Show derived keys.
fn cmd_keys_show(cli: &Cli, source: &str) -> Result<()> {
    cmd_keys_derive(cli, source)
}

/// Register public keys on-chain.
fn cmd_register(cli: &Cli, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let note_privkey = keys::derive_note_private_key(source, &cli.network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let (enc_pub, _enc_priv) = keys::derive_encryption_keypair(source, &cli.network)?;

    let address = stellar::keys_address(source, &cli.network)?;

    transaction::register(&cfg, &cli.network, source, &address, &note_pubkey, &enc_pub)?;
    println!("Public keys registered on-chain for {source} ({address})");
    Ok(())
}

/// Deposit tokens.
fn cmd_deposit(cli: &Cli, amount: u64, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;

    // Sync first to get latest state
    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::deposit(&database, &cfg, &cli.network, source, amount)?;
    println!("Deposit of {amount} stroops submitted successfully.");
    Ok(())
}

/// Withdraw tokens.
fn cmd_withdraw(cli: &Cli, amount: u64, to: &str, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;

    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::withdraw(&database, &cfg, &cli.network, source, to, amount)?;
    println!("Withdrawal of {amount} stroops submitted successfully.");
    Ok(())
}

/// Transfer tokens privately.
fn cmd_transfer(cli: &Cli, amount: u64, to: &str, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;

    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::transfer(&database, &cfg, &cli.network, source, to, amount)?;
    println!("Transfer of {amount} stroops submitted successfully.");
    Ok(())
}

/// List notes.
fn cmd_notes_list(cli: &Cli, source: &str) -> Result<()> {
    let database = db::Database::open(&cli.network)?;
    let note_privkey = keys::derive_note_private_key(source, &cli.network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);

    let notes = database.list_notes(&pubkey_hex)?;
    display::print_notes(&notes);
    Ok(())
}

/// Scan for new notes.
fn cmd_notes_scan(cli: &Cli, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    let database = db::Database::open(&cli.network)?;

    // Sync first
    sync::sync_all(&database, &cfg, &cli.network)?;

    let found = notes::scan_notes(&database, source, &cli.network)?;
    println!("Scan complete. Found {found} new note(s).");
    Ok(())
}

/// Export a note.
fn cmd_notes_export(note_id: &str) -> Result<()> {
    notes::export_note(note_id)
}

/// Import a note.
fn cmd_notes_import(file: &str) -> Result<()> {
    notes::import_note(file)
}

/// Add a member to ASP.
fn cmd_admin_add_member(cli: &Cli, account: &str, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    admin::add_member(&cfg, &cli.network, account, source)?;
    println!("Member added successfully.");
    Ok(())
}

/// Remove a member from ASP.
fn cmd_admin_remove_member(cli: &Cli, account: &str, source: &str) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    admin::remove_member(&cfg, &cli.network, account, source)?;
    println!("Member removed successfully.");
    Ok(())
}

/// Update ASP admin.
fn cmd_admin_update_admin(
    cli: &Cli,
    new_admin: &str,
    contract: Option<&str>,
    source: &str,
) -> Result<()> {
    let cfg = config::load_config(&cli.network)?;
    admin::update_admin(&cfg, &cli.network, new_admin, contract, source)?;
    println!("Admin updated successfully.");
    Ok(())
}
