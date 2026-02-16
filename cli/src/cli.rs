//! Clap derive structs for all CLI commands.

use clap::{Parser, Subcommand};

/// Stellar CLI plugin for private payments.
#[derive(Parser)]
#[command(name = "stellar-spp", about = "Private payments on Stellar")]
pub struct Cli {
    /// Stellar network name (e.g., testnet, mainnet, standalone)
    #[arg(long, global = true, default_value = "testnet")]
    pub network: String,

    /// Pool contract address (overrides deployment config)
    #[arg(long, global = true)]
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
