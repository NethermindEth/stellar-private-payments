//! Stellar CLI plugin for private payments.
//!
//! Invoked as `stellar spp <command>`.

mod admin;
mod cli;
mod config;
mod crypto;
mod db;
mod display;
mod keys;
mod merkle;
mod notes;
mod proof;
mod stellar;
mod sync;
mod transaction;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{AdminCommand, Cli, Commands, KeysCommand, NotesCommand, PoolCommand};

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
            NotesCommand::Export { note_id } => cmd_notes_export(&cli, note_id),
            NotesCommand::Import { file } => cmd_notes_import(&cli, file),
        },
        Commands::Pool(ref sub) => match sub {
            PoolCommand::Add {
                name,
                pool_id,
                asp_membership,
                asp_non_membership,
                verifier,
                deployer,
                admin,
            } => cmd_pool_add(
                &cli,
                name,
                pool_id.as_deref(),
                asp_membership.as_deref(),
                asp_non_membership.as_deref(),
                verifier.as_deref(),
                deployer.as_deref(),
                admin.as_deref(),
            ),
            PoolCommand::Ls => cmd_pool_ls(&cli),
            PoolCommand::Rm { name } => cmd_pool_rm(&cli, name),
            PoolCommand::Use { name } => cmd_pool_use(&cli, name),
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

/// Resolve the pool name from `--pool`, env, or default in network config.
fn resolve_pool(cli: &Cli) -> Result<String> {
    if let Some(ref pool) = cli.pool {
        return Ok(pool.clone());
    }
    config::maybe_migrate(&cli.network)?;
    let net_cfg = config::load_network_config(&cli.network)?;
    net_cfg.default_pool.context(
        "No default pool set. Use --pool <name> or run: stellar spp pool use <name>",
    )
}

/// Initialize deployment config and perform initial sync.
fn cmd_init(cli: &Cli) -> Result<()> {
    let pool_name = cli.pool.as_deref().unwrap_or("default");
    config::maybe_migrate(&cli.network)?;
    let cfg = config::load_or_create_config(&cli.network, pool_name)?;

    // Set as default if this is the first pool
    let mut net_cfg = config::load_network_config(&cli.network)?;
    if net_cfg.default_pool.is_none() {
        net_cfg.default_pool = Some(pool_name.to_string());
        config::save_network_config(&cli.network, &net_cfg)?;
    }

    println!("Deployment config for network '{}', pool '{pool_name}':", cli.network);
    println!("  Pool:               {}", cfg.pool);
    println!("  ASP Membership:     {}", cfg.asp_membership);
    println!("  ASP Non-Membership: {}", cfg.asp_non_membership);
    println!("  Verifier:           {}", cfg.verifier);

    let database = db::Database::open(&cli.network, pool_name)?;
    database.migrate()?;
    println!(
        "\nDatabase initialized at {}",
        db::db_path(&cli.network, pool_name)?.display()
    );

    println!("\nRunning initial sync...");
    sync::sync_all(&database, &cfg, &cli.network)?;
    println!("Initial sync complete.");
    Ok(())
}

/// Incremental event sync.
fn cmd_sync(cli: &Cli) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;
    sync::sync_all(&database, &cfg, &cli.network)?;
    println!("Sync complete.");
    Ok(())
}

/// Show sync status, balances, contract info.
fn cmd_status(cli: &Cli, source: Option<&str>) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;

    let pool_count = database.pool_leaf_count()?;
    let nullifier_count = database.nullifier_count()?;
    let asp_count = database.asp_leaf_count()?;

    println!("Network: {}", cli.network);
    println!("Pool: {pool_name}");
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
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
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
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;

    // Sync first to get latest state
    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::deposit(&database, &cfg, &cli.network, source, amount)?;
    println!("Deposit of {amount} stroops submitted successfully.");
    Ok(())
}

/// Withdraw tokens.
fn cmd_withdraw(cli: &Cli, amount: u64, to: &str, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;

    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::withdraw(&database, &cfg, &cli.network, source, to, amount)?;
    println!("Withdrawal of {amount} stroops submitted successfully.");
    Ok(())
}

/// Transfer tokens privately.
fn cmd_transfer(cli: &Cli, amount: u64, to: &str, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;

    sync::sync_all(&database, &cfg, &cli.network)?;

    transaction::transfer(&database, &cfg, &cli.network, source, to, amount)?;
    println!("Transfer of {amount} stroops submitted successfully.");
    Ok(())
}

/// List notes.
fn cmd_notes_list(cli: &Cli, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let database = db::Database::open(&cli.network, &pool_name)?;
    let note_privkey = keys::derive_note_private_key(source, &cli.network)?;
    let note_pubkey = crypto::derive_public_key(&note_privkey);
    let pubkey_hex = crypto::scalar_to_hex_be(&note_pubkey);

    let notes = database.list_notes(&pubkey_hex)?;
    display::print_notes(&notes);
    Ok(())
}

/// Scan for new notes.
fn cmd_notes_scan(cli: &Cli, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    let database = db::Database::open(&cli.network, &pool_name)?;

    // Sync first
    sync::sync_all(&database, &cfg, &cli.network)?;

    let found = notes::scan_notes(&database, source, &cli.network)?;
    println!("Scan complete. Found {found} new note(s).");
    Ok(())
}

/// Export a note.
fn cmd_notes_export(cli: &Cli, note_id: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let database = db::Database::open(&cli.network, &pool_name)?;
    notes::export_note(&database, note_id)
}

/// Import a note.
fn cmd_notes_import(cli: &Cli, file: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let database = db::Database::open(&cli.network, &pool_name)?;
    notes::import_note(&database, file)
}

// ========== Pool subcommands ==========

/// Add a pool from deployments.json or explicit flags.
#[allow(clippy::too_many_arguments)]
fn cmd_pool_add(
    cli: &Cli,
    name: &str,
    pool_id: Option<&str>,
    asp_membership: Option<&str>,
    asp_non_membership: Option<&str>,
    verifier: Option<&str>,
    deployer: Option<&str>,
    admin: Option<&str>,
) -> Result<()> {
    config::validate_pool_name(name)?;
    config::maybe_migrate(&cli.network)?;

    let cfg = if let Some(pool_id) = pool_id {
        // Build from explicit flags — contract IDs required when not using deployments.json
        config::DeploymentConfig {
            network: cli.network.clone(),
            pool: pool_id.to_string(),
            asp_membership: asp_membership
                .context("--asp-membership is required when --pool-id is set")?
                .to_string(),
            asp_non_membership: asp_non_membership
                .context("--asp-non-membership is required when --pool-id is set")?
                .to_string(),
            verifier: verifier
                .context("--verifier is required when --pool-id is set")?
                .to_string(),
            deployer: deployer.unwrap_or("").to_string(),
            admin: admin.unwrap_or("").to_string(),
            initialized: true,
        }
    } else {
        config::load_from_deployments_json(&cli.network)?
    };

    config::save_pool_config(&cli.network, name, &cfg)?;

    // Set as default if first pool
    let mut net_cfg = config::load_network_config(&cli.network)?;
    if net_cfg.default_pool.is_none() {
        net_cfg.default_pool = Some(name.to_string());
        config::save_network_config(&cli.network, &net_cfg)?;
        println!("Pool '{name}' added and set as default.");
    } else {
        println!("Pool '{name}' added.");
    }
    println!("  Pool contract: {}", cfg.pool);

    Ok(())
}

/// List pools for the current network.
fn cmd_pool_ls(cli: &Cli) -> Result<()> {
    config::maybe_migrate(&cli.network)?;
    let net_cfg = config::load_network_config(&cli.network)?;
    let pools = config::list_pools(&cli.network)?;

    if pools.is_empty() {
        println!("No pools configured for network '{}'.", cli.network);
        println!("Run `stellar spp init` or `stellar spp pool add <name>` to add one.");
        return Ok(());
    }

    println!("Pools for network '{}':", cli.network);
    for name in &pools {
        let marker = if net_cfg.default_pool.as_deref() == Some(name) {
            " (default)"
        } else {
            ""
        };
        match config::load_pool_config(&cli.network, name) {
            Ok(cfg) => println!("  {name}{marker}  pool={}", cfg.pool),
            Err(_) => println!("  {name}{marker}  (error loading config)"),
        }
    }

    Ok(())
}

/// Remove a pool.
fn cmd_pool_rm(cli: &Cli, name: &str) -> Result<()> {
    config::maybe_migrate(&cli.network)?;

    // Check pool exists
    let pools = config::list_pools(&cli.network)?;
    if !pools.contains(&name.to_string()) {
        anyhow::bail!("Pool '{name}' not found for network '{}'.", cli.network);
    }

    config::remove_pool(&cli.network, name)?;

    // Update default if we removed the default pool
    let mut net_cfg = config::load_network_config(&cli.network)?;
    if net_cfg.default_pool.as_deref() == Some(name) {
        let remaining = config::list_pools(&cli.network)?;
        net_cfg.default_pool = remaining.into_iter().next();
        config::save_network_config(&cli.network, &net_cfg)?;
        if let Some(ref new_default) = net_cfg.default_pool {
            println!("Pool '{name}' removed. Default changed to '{new_default}'.");
        } else {
            println!("Pool '{name}' removed. No pools remaining.");
        }
    } else {
        println!("Pool '{name}' removed.");
    }

    Ok(())
}

/// Set the default pool.
fn cmd_pool_use(cli: &Cli, name: &str) -> Result<()> {
    config::maybe_migrate(&cli.network)?;

    // Verify pool exists
    let pools = config::list_pools(&cli.network)?;
    if !pools.contains(&name.to_string()) {
        anyhow::bail!("Pool '{name}' not found for network '{}'.", cli.network);
    }

    let mut net_cfg = config::load_network_config(&cli.network)?;
    net_cfg.default_pool = Some(name.to_string());
    config::save_network_config(&cli.network, &net_cfg)?;
    println!("Default pool for network '{}' set to '{name}'.", cli.network);

    Ok(())
}

/// Add a member to ASP.
fn cmd_admin_add_member(cli: &Cli, account: &str, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    admin::add_member(&cfg, &cli.network, account, source)?;
    println!("Member added successfully.");
    Ok(())
}

/// Remove a member from ASP.
fn cmd_admin_remove_member(cli: &Cli, account: &str, source: &str) -> Result<()> {
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
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
    let pool_name = resolve_pool(cli)?;
    let cfg = config::load_config(&cli.network, &pool_name)?;
    admin::update_admin(&cfg, &cli.network, new_admin, contract, source)?;
    println!("Admin updated successfully.");
    Ok(())
}
