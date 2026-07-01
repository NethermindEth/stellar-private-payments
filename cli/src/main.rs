mod account;
mod artifacts;
mod cmd;
mod config;
mod onboard;
mod output;
mod session;
mod signer;
mod stellar_cli;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::{
    CliConfig, CliConfigOverrides, default_config_path, load_file_config, resolve_config_path,
    validate_pool,
};

#[derive(Debug, Parser)]
#[command(
    name = "spp",
    about = "CLI for Stellar Private Payments",
    version
)]
struct Cli {
    /// Config file path (default: ~/.config/spp/config.toml when
    /// present)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Override deployments.json (default: embedded testnet deployment)
    #[arg(long, global = true)]
    deployment: Option<PathBuf>,

    /// Soroban RPC URL (defaults from deployment network)
    #[arg(long, global = true)]
    rpc_url: Option<String>,

    /// Local wallet and indexer data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// `stellar keys` alias to sign with (register via `stellar keys generate`).
    /// Required for pool commands.
    #[arg(long, global = true, env = "STELLAR_ACCOUNT")]
    source_account: Option<String>,

    /// Config directory for the `stellar` CLI (passed as --config-dir; default:
    /// ~/.config/stellar)
    #[arg(long, global = true)]
    stellar_config_dir: Option<PathBuf>,

    /// Directory with policy_tx_2_2.{wasm,r1cs} (default:
    /// target/circuits-artifacts/<profile>)
    #[arg(long, global = true)]
    circuits_dir: Option<PathBuf>,

    /// Emit JSON instead of human-readable output
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Show resolved CLI configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Read on-chain deployment state
    Chain {
        #[command(subcommand)]
        command: ChainCommands,
    },
    /// Pool wallet operations (requires --source-account)
    Pool {
        /// Pool contract id (C…)
        pool_id: String,
        #[command(subcommand)]
        command: PoolCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Print deployment, RPC, and local paths
    Show,
    /// Write a commented config template to the config file path
    Init,
}

#[derive(Debug, Subcommand)]
enum ChainCommands {
    /// List pools from the deployment file
    Pools,
    /// Fetch on-chain state for all enabled pools
    Status,
    /// Fetch ASP membership and non-membership state
    Asp,
}

#[derive(Debug, Subcommand)]
enum PoolCommands {
    /// Show spendable private balance for the active pool
    Balance,
    /// List notes for the active pool
    Notes,
    /// Deposit public tokens into the pool
    Deposit {
        /// Amount in stroops
        amount: String,
    },
    /// Private transfer to a registered recipient
    Transfer {
        /// Amount in stroops
        amount: String,
        #[command(subcommand)]
        recipient: session::TransferRecipientCmd,
    },
    /// Withdraw to a public Stellar address
    Withdraw {
        /// Amount in stroops
        amount: String,
        /// Public recipient Stellar address (G…); defaults to the signing
        /// account
        #[arg(long)]
        to: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.clone());
    let file_config = match config_path.as_deref() {
        Some(path) => Some(load_file_config(path)?),
        None => None,
    };
    let config = CliConfig::load(
        config_path,
        file_config,
        CliConfigOverrides {
            deployment_path: cli.deployment,
            rpc_url: cli.rpc_url,
            data_dir: cli.data_dir,
            source_account: cli.source_account,
            stellar_config_dir: cli.stellar_config_dir,
            circuits_dir: cli.circuits_dir,
        },
    )?;

    match cli.command {
        Commands::Config { command } => match command {
            ConfigCommands::Show => cmd::config::show(&config, cli.json),
            ConfigCommands::Init => {
                let path = cli.config.clone().unwrap_or_else(default_config_path);
                cmd::config::init(&path, cli.json)
            }
        },
        Commands::Chain { command } => match command {
            ChainCommands::Pools => cmd::chain::pools(&config, cli.json),
            ChainCommands::Status => cmd::chain::status(&config, cli.json),
            ChainCommands::Asp => cmd::chain::asp(&config, cli.json),
        },
        Commands::Pool { pool_id, command } => {
            let config = config.with_pool(pool_id);
            validate_pool(config.require_pool()?, &config.deployment)?;
            let circuits_dir = config.circuits_dir.as_deref();
            match command {
                PoolCommands::Balance => cmd::pool::balance(&config, cli.json, circuits_dir),
                PoolCommands::Notes => cmd::pool::notes(&config, cli.json, circuits_dir),
                PoolCommands::Deposit { amount } => {
                    cmd::pool::deposit(&config, &amount, cli.json, circuits_dir)
                }
                PoolCommands::Transfer { amount, recipient } => {
                    cmd::pool::transfer(&config, &amount, &recipient, cli.json, circuits_dir)
                }
                PoolCommands::Withdraw { amount, to } => {
                    cmd::pool::withdraw(&config, &amount, to.as_deref(), cli.json, circuits_dir)
                }
            }
        }
    }
}
