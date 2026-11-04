//! `gvk` — Global View Key audit of pool-gvk pools.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Subcommand;
use stellar_private_payments::{
    gvk::{GvkOutputSlot, GvkSpentInput},
    types::GvkAuthoritySetting,
    zk::gvk::GvkAuditedNote,
};

use crate::{config::CliConfig, output, session::readonly_client};

#[derive(Debug, Subcommand)]
pub enum GvkCommands {
    /// Decrypt the private transacts of a pool-gvk pool, oldest first
    ///
    /// Syncs local storage first, so it unlocks it with --storage-account or
    /// --account. With --json, prints one JSON object per transact.
    Audit {
        /// Pool contract id (C…)
        #[arg(long)]
        pool: String,
        /// GVK keypair JSON (`privateKey`, `publicKey`) as `gvkey-gen` writes
        /// it
        #[arg(long)]
        key_file: PathBuf,
        /// Maximum number of transacts to print (default: all)
        #[arg(long)]
        limit: Option<u32>,
    },
}

pub fn run(config: &CliConfig, command: GvkCommands, json: bool) -> Result<()> {
    match command {
        GvkCommands::Audit {
            pool,
            key_file,
            limit,
        } => audit(config, &pool, &key_file, limit, json),
    }
}

// No value fields: the key file holds a secret.
#[tracing::instrument(
    name = "cmd_gvk_audit",
    skip_all,
    fields(correlation_id = %stellar_private_payments::types::correlation_id_or_new())
)]
fn audit(
    config: &CliConfig,
    pool: &str,
    key_file: &Path,
    limit: Option<u32>,
    json: bool,
) -> Result<()> {
    let key = read_key_file(key_file)?;
    let network = config.resolve_network()?;
    let client = readonly_client(config, &network)?;
    let mut audit = client
        .gvk_authority(key.private_key)?
        .audit(pool)
        .with_context(|| format!("open GVK audit of {pool}"))?;

    let mut count = 0u32;
    while limit.is_none_or(|limit| count < limit) {
        let Some(tx) = audit.next_tx().context("audit next transact")? else {
            break;
        };
        count = count.saturating_add(1);
        if json {
            println!("{}", serde_json::to_string(&tx)?);
            continue;
        }
        output::print_section(&format!("transact {count} (ledger {})", tx.ledger));
        for (i, slot) in tx.outputs.iter().enumerate() {
            output::print_kv(&format!("  output[{i}]"), output_line(slot));
        }
        for (i, slot) in tx.inputs.iter().enumerate() {
            output::print_kv(&format!("  input[{i}]"), input_line(slot));
        }
    }
    if !json && count == 0 {
        println!("(no private transacts)");
    }
    Ok(())
}

fn read_key_file(path: &Path) -> Result<GvkAuthoritySetting> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read GVK key file {}", path.display()))?;
    let key: GvkAuthoritySetting = serde_json::from_str(&raw)
        .with_context(|| format!("parse GVK key file {}", path.display()))?;
    key.validate_consistency()?;
    Ok(key)
}

fn output_line(slot: &GvkOutputSlot) -> String {
    format!(
        "commitment={} {}",
        slot.commitment,
        note_text(slot.note.as_ref())
    )
}

fn input_line(slot: &GvkSpentInput) -> String {
    format!(
        "nullifier={} {}",
        slot.nullifier,
        note_text(slot.note.as_ref())
    )
}

fn note_text(note: Option<&GvkAuditedNote>) -> String {
    let Some(note) = note else {
        return "(no note decrypted)".to_string();
    };
    let amount = note
        .note
        .amount()
        .map(|amount| format!("{amount} base units"))
        .unwrap_or_else(|_| "unreadable amount".to_string());
    format!("amount={amount} pk={}", note.note.pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_private_payments::types::BabyJubJubPoint;

    struct KeyFile(PathBuf);

    impl KeyFile {
        fn write(setting: &GvkAuthoritySetting) -> Self {
            static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "spp-gvk-key-{}-{}.json",
                std::process::id(),
                RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::write(
                &path,
                serde_json::to_string(setting).expect("serialize key"),
            )
            .expect("write key file");
            Self(path)
        }
    }

    impl Drop for KeyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_generated_key_file_is_read_back() {
        let setting = GvkAuthoritySetting::generate().expect("generate key");
        let file = KeyFile::write(&setting);
        let read = read_key_file(&file.0).expect("read key file");
        assert!(read == setting);
    }

    #[test]
    fn a_key_file_whose_public_key_does_not_match_is_refused() {
        let mut setting = GvkAuthoritySetting::generate().expect("generate key");
        let other = GvkAuthoritySetting::generate().expect("generate key");
        setting.public_key = BabyJubJubPoint::clone(&other.public_key);
        let file = KeyFile::write(&setting);
        assert!(read_key_file(&file.0).is_err());
    }
}
