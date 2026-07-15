mod account;
mod artifacts;
mod cmd;
mod config;
mod explorer;
mod logging;
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
};
use onboard::OnboardArgs;

#[derive(Debug, Parser)]
#[command(
    name = "spp",
    about = "CLI for Stellar Private Payments",
    long_about = "CLI for Stellar Private Payments.\n\n\
        Accounts are managed by the Stellar CLI (`stellar keys`) and passed with \
        --account <alias>; the network (RPC + passphrase) is resolved from the Stellar CLI \
        (`stellar network`). Run `spp onboard` first to accept the disclaimer and derive your keys.\n\n\
        Repository: https://github.com/NethermindEth/stellar-private-payments",
    version
)]
struct Cli {
    /// Config file path (default: ~/.config/spp/config.toml when present)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Override deployments.json (default: embedded testnet deployment)
    #[arg(long, global = true)]
    deployment: Option<PathBuf>,

    /// Stellar CLI network name (default: the deployment's network, e.g.
    /// testnet)
    #[arg(long, global = true)]
    network: Option<String>,

    /// Local wallet and indexer data directory
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Config directory for the `stellar` CLI (passed as --config-dir)
    #[arg(long, global = true)]
    stellar_config_dir: Option<PathBuf>,

    /// Directory with policy_tx_2_2[_{A,B,AB}].{wasm,r1cs}
    /// (default: target/circuits-artifacts/release in debug builds,
    /// data_dir/circuits otherwise)
    #[arg(long, global = true)]
    circuits_dir: Option<PathBuf>,

    /// `stellar keys` alias to act as (required by account commands)
    #[arg(long, global = true, env = "STELLAR_ACCOUNT")]
    account: Option<String>,

    /// Emit JSON instead of human-readable output
    #[arg(long, global = true)]
    json: bool,

    /// Increase log verbosity (-v debug, -vv trace)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Accept the disclaimer, derive keys, and configure
    /// bootnode/explorer/registration
    Onboard {
        /// Accept the disclaimer non-interactively
        #[arg(long)]
        accept: bool,
        /// Set the bootnode archive URL
        #[arg(long)]
        bootnode_url: Option<String>,
        /// Disable the bootnode fallback
        #[arg(long)]
        no_bootnode: bool,
        /// Set the explorer base URL
        #[arg(long)]
        explorer_url: Option<String>,
        /// Register public keys on-chain during onboarding
        #[arg(long)]
        register: bool,
        /// Skip public-key registration
        #[arg(long)]
        no_register: bool,
    },
    /// Pools, balances, contracts, network, and registration status
    /// Omit the pool to show all enabled pools, or pass one pool contract id
    Overview {
        /// Pool contract id (C…); omit for all enabled pools
        pool: Option<String>,
    },
    /// Latest operational events
    Feed {
        /// Number of items to show (default 5)
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Inspect config and update explorer / bootnode settings
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Show your note and encryption public keys
    Keys,
    /// Reveal the ASP secret (keep it private)
    AspSecret,
    /// Print the CLI version
    Version,
    /// Register your public keys in the on-chain address book
    Register,
    /// Deposit public tokens into a pool
    Deposit {
        /// Pool contract id (C…)
        pool: String,
        /// Amount in token units (e.g. 1 or 0.0001)
        amount: String,
    },
    /// Private transfer to a recipient
    Transfer {
        /// Pool contract id (C…)
        pool: String,
        /// Amount in token units (e.g. 1 or 0.0001)
        amount: String,
        /// Recipient Stellar address (G…); looked up in the registry
        #[arg(long)]
        to: Option<String>,
        /// Recipient BN254 note public key (hex)
        #[arg(long)]
        note_key: Option<String>,
        /// Recipient X25519 encryption public key (hex)
        #[arg(long)]
        encryption_key: Option<String>,
    },
    /// Withdraw to a public Stellar address
    Withdraw {
        /// Pool contract id (C…)
        pool: String,
        /// Amount in token units (e.g. 1 or 0.0001)
        amount: String,
        /// Public recipient (G…); defaults to the signing account
        #[arg(long)]
        to: Option<String>,
    },
    /// Show the operating disclaimer and acceptance status
    Disclaimer,
    /// Show the license / distribution notice
    License,
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Print deployment, network, local paths, and settings
    Show,
    /// Write a commented config template to the config file path
    Init,
    /// Set the explorer base URL (stored in the local database)
    SetExplorer {
        /// Explorer base URL, e.g. https://stellar.expert/explorer/testnet
        url: String,
    },
    /// Set or disable the bootnode archive URL (stored in the local database)
    SetBootnode {
        /// Bootnode archive URL
        url: Option<String>,
        /// Disable the bootnode fallback
        #[arg(long)]
        disable: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(cli.verbose, cli.json);
    let json = cli.json;
    let config_flag = cli.config.clone();

    let config_path = resolve_config_path(config_flag.clone());
    let file_config = match config_path.as_deref() {
        Some(path) => Some(load_file_config(path)?),
        None => None,
    };
    let config = CliConfig::load(
        config_path,
        file_config,
        CliConfigOverrides {
            deployment_path: cli.deployment,
            network: cli.network,
            data_dir: cli.data_dir,
            account: cli.account,
            stellar_config_dir: cli.stellar_config_dir,
            circuits_dir: cli.circuits_dir,
        },
    )?;

    match cli.command {
        Commands::Onboard {
            accept,
            bootnode_url,
            no_bootnode,
            explorer_url,
            register,
            no_register,
        } => onboard::run(
            &config,
            &OnboardArgs {
                accept,
                bootnode_url,
                no_bootnode,
                explorer_url,
                register,
                no_register,
            },
            json,
        ),
        Commands::Overview { pool } => cmd::overview::run(&config, pool.as_deref(), json),
        Commands::Feed { limit } => cmd::feed::run(&config, limit, json),
        Commands::Config { command } => match command {
            ConfigCommands::Show => cmd::config::show(&config, json),
            ConfigCommands::Init => {
                let path = config_flag.unwrap_or_else(default_config_path);
                cmd::config::init(&path, json)
            }
            ConfigCommands::SetExplorer { url } => cmd::config::set_explorer(&config, &url, json),
            ConfigCommands::SetBootnode { url, disable } => {
                cmd::config::set_bootnode(&config, url.as_deref(), disable, json)
            }
        },
        Commands::Keys => cmd::keys::show(&config, json),
        Commands::AspSecret => cmd::keys::asp_secret(&config, json),
        Commands::Version => cmd::version::run(json),
        Commands::Register => cmd::register::run(&config, json),
        Commands::Deposit { pool, amount } => cmd::pool::deposit(&config, &pool, &amount, json),
        Commands::Transfer {
            pool,
            amount,
            to,
            note_key,
            encryption_key,
        } => cmd::pool::transfer(
            &config,
            &pool,
            &amount,
            to.as_deref(),
            note_key.as_deref(),
            encryption_key.as_deref(),
            json,
        ),
        Commands::Withdraw { pool, amount, to } => {
            cmd::pool::withdraw(&config, &pool, &amount, to.as_deref(), json)
        }
        Commands::Disclaimer => cmd::disclaimer::run(&config, json),
        Commands::License => cmd::license::run(&config, json),
    }
}
