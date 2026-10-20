//! Generate, validate, and inspect Global View Key (GVK) admin authority keys.

use std::{io::Write, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{ArgAction, Parser, Subcommand};
use stellar_private_payments::{
    LocalStorage,
    state::{database_key::DatabaseKey, native_wallet},
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
    /// Stellar CLI identity (`stellar keys`) that unlocks `--db`.
    #[arg(long = "storage-account", env = "SPP_STORAGE_ACCOUNT")]
    storage_account: Option<String>,
    /// Config directory for the `stellar` CLI (passed as `--config-dir`).
    #[arg(long = "stellar-config-dir")]
    stellar_config_dir: Option<PathBuf>,
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
    /// Stellar CLI identity (`stellar keys`) that unlocks `--db`.
    #[arg(long = "storage-account", env = "SPP_STORAGE_ACCOUNT")]
    storage_account: String,
    /// Config directory for the `stellar` CLI (passed as `--config-dir`).
    #[arg(long = "stellar-config-dir")]
    stellar_config_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Generate(args) => generate(args),
        Commands::Validate(args) => validate(args),
        Commands::Show(args) => show(args),
    }
}

fn generate(args: GenerateArgs) -> Result<()> {
    generate_with(args, |path, account, config_dir| {
        native_wallet::unlock_with_stellar(path, account, config_dir)
    })
}

fn generate_with(
    args: GenerateArgs,
    mut unlock: impl FnMut(&std::path::Path, &str, Option<&std::path::Path>) -> Result<DatabaseKey>,
) -> Result<()> {
    if args.out_file.is_none() && args.db.is_none() {
        bail!("generate requires --out-file, --db, or both");
    }

    if let Some(path) = &args.out_file
        && path.exists()
        && !args.force
    {
        bail!(
            "refusing to overwrite existing file `{}`; pass --force",
            path.display()
        );
    }

    let storage = match &args.db {
        Some(path) => {
            let account = args.storage_account.as_deref().ok_or_else(|| {
                anyhow!("--db requires --storage-account <ALIAS> (or SPP_STORAGE_ACCOUNT)")
            })?;
            let (owner_lock, storage) = open_storage_with(
                path,
                account,
                args.stellar_config_dir.as_deref(),
                &mut unlock,
            )?;
            if storage.get_gvk_authority_setting()?.is_some() && !args.force {
                bail!(
                    "wallet database `{}` already has a saved GVK authority setting; pass --force to overwrite",
                    path.display()
                );
            }
            Some((path, owner_lock, storage))
        }
        None => None,
    };

    let setting = GvkAuthoritySetting::generate().context("generate GVK authority keypair")?;

    if let Some(path) = &args.out_file {
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

    if let Some((path, _owner_lock, storage)) = storage {
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
    let setting = show_with(args, |path, account, config_dir| {
        native_wallet::unlock_with_stellar(path, account, config_dir)
    })?;
    println!("{}", serde_json::to_string_pretty(&setting.public_key)?);
    Ok(())
}

fn show_with(
    args: ShowArgs,
    mut unlock: impl FnMut(&std::path::Path, &str, Option<&std::path::Path>) -> Result<DatabaseKey>,
) -> Result<GvkAuthoritySetting> {
    let (_owner_lock, storage) = open_storage_with(
        &args.db,
        &args.storage_account,
        args.stellar_config_dir.as_deref(),
        &mut unlock,
    )?;
    let setting = storage
        .get_gvk_authority_setting()?
        .ok_or_else(|| anyhow!("no GVK authority setting saved in {}", args.db.display()))?;
    setting.validate_consistency()?;
    Ok(setting)
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

fn lock_storage_owner(path: &std::path::Path) -> Result<std::fs::File> {
    let absolute = std::path::absolute(path)?;
    if let Some(parent) = absolute.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let mut owner_path = absolute.into_os_string();
    owner_path.push(".owner");
    let owner_path = PathBuf::from(owner_path);
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let owner = opts
        .open(&owner_path)
        .with_context(|| format!("open storage lock {}", owner_path.display()))?;
    owner
        .try_lock()
        .context("storage database is in use by another process")?;
    Ok(owner)
}

fn open_storage_with(
    path: &std::path::Path,
    storage_account: &str,
    stellar_config_dir: Option<&std::path::Path>,
    unlock: &mut impl FnMut(&std::path::Path, &str, Option<&std::path::Path>) -> Result<DatabaseKey>,
) -> Result<(std::fs::File, LocalStorage)> {
    let owner_lock = lock_storage_owner(path)?;
    let is_new = !path.exists();
    let key = unlock(path, storage_account, stellar_config_dir)
        .with_context(|| format!("unlock wallet database at {}", path.display()))?;
    let storage = LocalStorage::open_with_key(&path.to_string_lossy(), &key)
        .with_context(|| format!("open wallet database at {}", path.display()))?;
    // New sqlite files default to a world-readable mode; harden like
    // `write_private_file`.
    #[cfg(unix)]
    if is_new {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    Ok((owner_lock, storage))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use stellar_private_payments::state::database_key::OpenPurpose;

    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Result<Self> {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let dir = std::env::temp_dir().join(format!(
                "gvkey-gen-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_unlock(
        path: &std::path::Path,
        _account: &str,
        _config_dir: Option<&std::path::Path>,
    ) -> Result<DatabaseKey> {
        let exists = std::fs::metadata(path).is_ok_and(|m| m.len() > 0);
        drop(LocalStorage::open_encrypted(
            &path.to_string_lossy(),
            DatabaseKey::new([0x42; 32]),
            if exists {
                OpenPurpose::OpenExisting
            } else {
                OpenPurpose::CreateNew
            },
        )?);
        Ok(DatabaseKey::new([0x42; 32]))
    }

    #[test]
    fn generate_and_show_round_trip_encrypted_db() -> Result<()> {
        let temp = TempDir::new()?;
        let db = temp.0.join("wallet.db");
        let out_file = temp.0.join("admin-d.json");

        generate_with(
            GenerateArgs {
                out_file: Some(out_file.clone()),
                db: Some(db.clone()),
                storage_account: Some("alice".into()),
                stellar_config_dir: None,
                force: false,
            },
            test_unlock,
        )?;

        let shown = show_with(
            ShowArgs {
                db: db.clone(),
                storage_account: "alice".into(),
                stellar_config_dir: None,
            },
            test_unlock,
        )?;
        let written: GvkAuthoritySetting =
            serde_json::from_str(&std::fs::read_to_string(&out_file)?)?;
        assert_eq!(shown.public_key, written.public_key);
        Ok(())
    }

    #[test]
    fn db_failure_does_not_leave_partial_out_file() -> Result<()> {
        let temp = TempDir::new()?;
        let db = temp.0.join("wallet.db");
        let first_out = temp.0.join("first.json");
        let second_out = temp.0.join("second.json");

        assert!(
            generate_with(
                GenerateArgs {
                    out_file: Some(first_out.clone()),
                    db: Some(db.clone()),
                    storage_account: None,
                    stellar_config_dir: None,
                    force: false,
                },
                test_unlock,
            )
            .is_err()
        );
        assert!(!first_out.exists());

        generate_with(
            GenerateArgs {
                out_file: None,
                db: Some(db.clone()),
                storage_account: Some("alice".into()),
                stellar_config_dir: None,
                force: false,
            },
            test_unlock,
        )?;

        assert!(
            generate_with(
                GenerateArgs {
                    out_file: Some(second_out.clone()),
                    db: Some(db),
                    storage_account: Some("alice".into()),
                    stellar_config_dir: None,
                    force: false,
                },
                test_unlock,
            )
            .is_err()
        );
        assert!(!second_out.exists());
        Ok(())
    }
}
