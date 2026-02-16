//! Clap derive structs for all CLI commands.

use clap::{Parser, Subcommand};

/// Stellar CLI plugin for private payments.
#[derive(Parser)]
#[command(name = "stellar-spp", about = "Private payments on Stellar")]
pub struct Cli {
    /// Stellar network name (matches `stellar network add` aliases)
    #[arg(long, global = true, default_value = "testnet", env = "STELLAR_NETWORK")]
    pub network: String,

    /// Pool name (use `stellar spp pool ls` to see available pools)
    #[arg(long, global = true, env = "STELLAR_SPP_POOL")]
    pub pool: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level commands.
#[derive(Subcommand)]
pub enum Commands {
    /// Set deployment config and perform initial sync
    Init,

    /// Incremental event sync
    Sync,

    /// Show sync status, balances, and contract info
    Status {
        /// Stellar identity to show balance for
        #[arg(long)]
        source: Option<String>,
    },

    /// Key management commands
    #[command(subcommand)]
    Keys(KeysCommand),

    /// Register public keys on-chain
    Register {
        /// Stellar identity (signing account)
        #[arg(long)]
        source: String,
    },

    /// Deposit tokens into the privacy pool
    Deposit {
        /// Amount in stroops
        amount: u64,
        /// Stellar identity (signing account)
        #[arg(long)]
        source: String,
    },

    /// Withdraw tokens from the privacy pool
    Withdraw {
        /// Amount in stroops
        amount: u64,
        /// Recipient identity
        #[arg(long)]
        to: String,
        /// Stellar identity (signing account)
        #[arg(long)]
        source: String,
    },

    /// Transfer tokens privately within the pool
    Transfer {
        /// Amount in stroops
        amount: u64,
        /// Recipient identity
        #[arg(long)]
        to: String,
        /// Stellar identity (signing account)
        #[arg(long)]
        source: String,
    },

    /// Note management commands
    #[command(subcommand)]
    Notes(NotesCommand),

    /// Pool management commands
    #[command(subcommand)]
    Pool(PoolCommand),

    /// ASP admin commands
    #[command(subcommand)]
    Admin(AdminCommand),
}

/// Key management subcommands.
#[derive(Subcommand)]
pub enum KeysCommand {
    /// Derive BN254/X25519 keys from a Stellar identity
    Derive {
        /// Stellar identity
        #[arg(long)]
        source: String,
    },
    /// Display derived keys for a Stellar identity
    Show {
        /// Stellar identity
        #[arg(long)]
        source: String,
    },
}

/// Note management subcommands.
#[derive(Subcommand)]
pub enum NotesCommand {
    /// List known notes
    List {
        /// Stellar identity (to filter notes)
        #[arg(long)]
        source: String,
    },
    /// Scan for new notes by decrypting encrypted outputs
    Scan {
        /// Stellar identity (to decrypt with)
        #[arg(long)]
        source: String,
    },
    /// Export a note to JSON
    Export {
        /// Note ID (commitment hex)
        note_id: String,
    },
    /// Import a note from a JSON file
    Import {
        /// Path to the JSON file
        file: String,
    },
}

/// Pool management subcommands.
#[derive(Subcommand)]
pub enum PoolCommand {
    /// Add a pool from deployments.json or explicit flags
    Add {
        /// Pool name
        name: String,
        /// Pool contract ID (overrides deployments.json)
        #[arg(long)]
        pool_id: Option<String>,
        /// ASP membership contract ID
        #[arg(long)]
        asp_membership: Option<String>,
        /// ASP non-membership contract ID
        #[arg(long)]
        asp_non_membership: Option<String>,
        /// Groth16 verifier contract ID
        #[arg(long)]
        verifier: Option<String>,
        /// Deployer G... address
        #[arg(long)]
        deployer: Option<String>,
        /// Admin G... address
        #[arg(long)]
        admin: Option<String>,
    },
    /// List pools for the current network
    Ls,
    /// Remove a pool
    Rm {
        /// Pool name
        name: String,
    },
    /// Set the default pool
    Use {
        /// Pool name
        name: String,
    },
}

/// ASP admin subcommands.
#[derive(Subcommand)]
pub enum AdminCommand {
    /// Add a member to the ASP membership tree
    AddMember {
        /// Target account identity (whose keys are being added)
        #[arg(long)]
        account: String,
        /// Admin identity (signing account)
        #[arg(long)]
        source: String,
    },
    /// Remove a member from the ASP membership tree
    RemoveMember {
        /// Target account identity
        #[arg(long)]
        account: String,
        /// Admin identity (signing account)
        #[arg(long)]
        source: String,
    },
    /// Update the ASP admin
    UpdateAdmin {
        /// New admin identity
        #[arg(long)]
        new_admin: String,
        /// ASP membership contract address
        #[arg(long)]
        contract: Option<String>,
        /// Current admin identity (signing account)
        #[arg(long)]
        source: String,
    },
}
