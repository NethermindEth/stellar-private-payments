//! Generate, validate, and inspect Global View Key (GVK) admin authority keys.

use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser, Subcommand};
use stellar_private_payments::{
    LocalStorage,
    types::{BabyJubJubPoint, GvkAuthoritySetting},
    zk::gvk::validate_global_view_public_key,
};

#[derive(Parser)]
#[command(
    name = "gvkey-gen",
    about = "Generate, validate, and inspect GVK admin authority keys"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a fresh GVK admin authority keypair.
    Generate(GenerateArgs),
    /// Validate a GVK public key: on-curve and not low-order.
    Validate(ValidateArgs),
    /// Print the public key of a keypair saved in a wallet database.
    Show(ShowArgs),
}

#[derive(clap::Args)]
struct GenerateArgs {
    /// Write the full keypair to this file.
    #[arg(long = "out-file")]
    out_file: Option<PathBuf>,
    /// Save the keypair as the GVK authority setting in a wallet database at
    /// this path.
    #[arg(long = "db")]
    db: Option<PathBuf>,
    /// Overwrite an existing output file or database authority setting.
    #[arg(long = "force", action = ArgAction::SetTrue)]
    force: bool,
}

#[derive(clap::Args)]
struct ValidateArgs {
    /// JSON file with the public key (`{"x":"0x..","y":"0x.."}`). Reads stdin
    /// if omitted.
    #[arg(long = "file")]
    file: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ShowArgs {
    /// Wallet database to read the saved authority setting from.
    #[arg(long = "db")]
    db: PathBuf,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Generate(args) => generate(args),
        Commands::Validate(args) => validate(args),
        Commands::Show(args) => show(args),
    }
}

fn generate(args: GenerateArgs) -> Result<()> {
    let setting = GvkAuthoritySetting::generate().context("generate GVK authority keypair")?;

    if args.out_file.is_none() && args.db.is_none() {
        bail!("generate requires --out-file, --db, or both");
    }

    if let Some(path) = &args.out_file {
        if path.exists() && !args.force {
            bail!(
                "refusing to overwrite existing file `{}`; pass --force",
                path.display()
            );
        }
        write_private_file(
            path,
            &format!("{}\n", serde_json::to_string_pretty(&setting)?),
        )
        .with_context(|| format!("write keypair to {}", path.display()))?;
        eprintln!(
            "wrote private keypair to {} — back it up, it cannot be recovered",
            path.display()
        );
    }

    if let Some(path) = &args.db {
        let storage = open_storage(path)?;
        if storage.get_gvk_authority_setting()?.is_some() && !args.force {
            bail!(
                "wallet database `{}` already has a saved GVK authority setting; pass --force to overwrite",
                path.display()
            );
        }
        storage.set_gvk_authority_setting(&setting)?;
        eprintln!("saved GVK authority setting to {}", path.display());
    }

    println!("{}", serde_json::to_string_pretty(&setting.public_key)?);
    Ok(())
}

fn validate(args: ValidateArgs) -> Result<()> {
    let raw = match &args.file {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?
        }
        None => std::io::read_to_string(std::io::stdin()).context("read stdin")?,
    };
    let key: BabyJubJubPoint = serde_json::from_str(&raw).context("parse public key JSON")?;
    validate_global_view_public_key(&key)?;
    println!("valid");
    Ok(())
}

fn show(args: ShowArgs) -> Result<()> {
    let storage = open_storage(&args.db)?;
    let setting = storage
        .get_gvk_authority_setting()?
        .ok_or_else(|| anyhow!("no GVK authority setting saved in {}", args.db.display()))?;
    setting.validate_consistency()?;
    println!("{}", serde_json::to_string_pretty(&setting.public_key)?);
    Ok(())
}

fn write_private_file(path: &std::path::Path, contents: &str) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // `mode()` only applies when the open call creates the file; force it
    // here too so an `--force` overwrite of a pre-existing file is covered.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents.as_bytes())?;
    Ok(())
}

fn open_storage(path: &std::path::Path) -> Result<LocalStorage> {
    LocalStorage::open(&path.to_string_lossy())
        .with_context(|| format!("open wallet database at {}", path.display()))
}
