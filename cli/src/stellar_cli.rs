//! Shared Stellar CLI integration for account operations, storage unlocking,
//! and contract code reads.

use std::{path::Path, process::Command};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::Value;

pub use stellar_private_payments::stellar_cli::{
    StellarNetwork, ensure_installed, network, public_key, sign_message, sign_tx, validate_alias,
};

/// A deployed contract's Wasm hash and the entries of all its Wasm's meta
/// sections, in order.
pub struct ContractCode {
    pub hash: String,
    pub meta: Vec<(String, String)>,
}

/// Reads a contract's Wasm hash and meta with `stellar`, or `None` for a
/// contract whose executable is not a Wasm, such as a Stellar asset contract.
///
/// # Errors
///
/// Returns an error when either command fails, or when its output does not
/// parse or names no contract instance.
pub fn contract_code(
    id: &str,
    network: &StellarNetwork,
    config_dir: Option<&Path>,
) -> Result<Option<ContractCode>> {
    let stellar = |args: &[&str]| -> Result<String> {
        let bin = std::env::var("STELLAR_BIN").unwrap_or_else(|_| "stellar".into());
        let mut cmd = Command::new(&bin);
        cmd.args(args).args([
            "--rpc-url",
            &network.rpc_url,
            "--network-passphrase",
            &network.passphrase,
        ]);
        if let Some(dir) = config_dir {
            cmd.arg("--config-dir").arg(dir);
        }
        let output = cmd.output().with_context(|| format!("run `{bin}`"))?;
        ensure!(
            output.status.success(),
            "`{bin} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        String::from_utf8(output.stdout).context("stellar CLI produced non-UTF-8 output")
    };
    // Not `contract info hash`: it fails on a Stellar asset contract, which
    // would then read as unreadable instead of as running no Wasm.
    let instance = stellar(&[
        "ledger",
        "entry",
        "fetch",
        "contract-data",
        "--contract",
        id,
        "--instance",
    ])?;
    let Some(hash) = wasm_hash_from_instance(&instance)? else {
        return Ok(None);
    };
    let meta = stellar(&[
        "contract",
        "info",
        "meta",
        "--contract-id",
        id,
        "--output",
        "json",
    ])?;
    Ok(Some(ContractCode {
        hash,
        meta: meta_entries(&meta)?,
    }))
}

/// Returns the Wasm hash a `ledger entry fetch --instance` reply names, or
/// `None` when the contract's executable is not a Wasm.
fn wasm_hash_from_instance(json: &str) -> Result<Option<String>> {
    let instance: Value = serde_json::from_str(json).context("parse contract instance")?;
    let executable = instance
        .pointer("/entries/0/val/contract_data/val/contract_instance/executable")
        .context("no contract instance")?;
    let Some(hash) = executable.get("wasm").and_then(Value::as_str) else {
        return Ok(None);
    };
    ensure!(
        hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
        "unexpected Wasm hash `{hash}`"
    );
    Ok(Some(hash.to_owned()))
}

/// Returns the entries a `contract info meta --output json` reply lists, in
/// order.
fn meta_entries(json: &str) -> Result<Vec<(String, String)>> {
    #[derive(Deserialize)]
    struct Entry {
        sc_meta_v0: KeyVal,
    }
    #[derive(Deserialize)]
    struct KeyVal {
        key: String,
        val: String,
    }
    // An empty Wasm meta prints nothing.
    let entries: Vec<Entry> = match json.trim() {
        "" => Vec::new(),
        json => serde_json::from_str(json).context("parse contract meta")?,
    };
    Ok(entries
        .into_iter()
        .map(|entry| (entry.sc_meta_v0.key, entry.sc_meta_v0.val))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ledger entry fetch contract-data --instance` from stellar 28.1.0 on
    /// testnet, with its storage left out.
    const INSTANCE: &str = r#"{"entries":[{
        "key":{"contract_data":{
            "contract":"CD5I","key":"ledger_key_contract_instance","durability":"persistent"}},
        "val":{"contract_data":{
            "ext":"v0","contract":"CD5I","key":"ledger_key_contract_instance",
            "durability":"persistent",
            "val":{"contract_instance":{"executable":EXECUTABLE,"storage":[]}}}},
        "lastModifiedLedgerSeq":5316526,"liveUntilLedgerSeq":5765805}],
        "latestLedger":5396744}"#;

    fn instance(executable: &str) -> String {
        INSTANCE.replace("EXECUTABLE", executable)
    }

    const HASH: &str = "673ceac68f897cd05c87219ebfedbe7e5928d6aa9ad456b383a6a4a7d4734c0b";

    #[test]
    fn an_instance_names_its_wasm_or_none_for_a_stellar_asset_contract() {
        let wasm = instance(&format!(r#"{{"wasm":"{HASH}"}}"#));
        assert_eq!(
            wasm_hash_from_instance(&wasm).expect("Wasm instance"),
            Some(HASH.to_owned())
        );
        let asset = instance(r#""stellar_asset""#);
        assert_eq!(wasm_hash_from_instance(&asset).expect("asset"), None);
        assert!(wasm_hash_from_instance(r#"{"entries":[],"latestLedger":1}"#).is_err());
        assert!(wasm_hash_from_instance(&instance(r#"{"wasm":"00ff"}"#)).is_err());
    }

    #[test]
    fn meta_lists_each_entry_in_order_and_empty_meta_lists_none() {
        let meta = r#"[{"sc_meta_v0":{"key":"rsver","val":"1.97.1"}},
            {"sc_meta_v0":{"key":"cliver",
                "val":"28.1.0#c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd"}}]"#;
        assert_eq!(
            meta_entries(meta).expect("meta"),
            [
                ("rsver".to_owned(), "1.97.1".to_owned()),
                (
                    "cliver".to_owned(),
                    "28.1.0#c0f4d0da891bbf214c08b8c5035ae6db80e9a3bd".to_owned()
                ),
            ]
        );
        assert_eq!(meta_entries("\n").expect("empty meta"), []);
    }
}
