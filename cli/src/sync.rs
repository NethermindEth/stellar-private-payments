//! Event fetching and incremental sync.
//!
//! Uses `stellar events --output json` to fetch contract events and stores
//! them in the SQLite database.
//!
//! The stellar CLI returns events with topics and values as base64-encoded
//! XDR `ScVal`. This module decodes them using the `stellar-xdr` crate.

use anyhow::{Context, Result};
use serde::Deserialize;
use stellar_xdr::curr::{self as xdr, ReadXdr, ScVal};

use crate::config::DeploymentConfig;
use crate::db::Database;
use crate::stellar;

/// A single event from `stellar events --output json`.
///
/// Topics and value are base64-encoded XDR `ScVal` strings.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StellarEvent {
    #[serde(rename = "type")]
    event_type: Option<String>,
    ledger: Option<u64>,
    #[serde(rename = "contractId")]
    contract_id: Option<String>,
    /// Base64-encoded XDR ScVal topic strings.
    topic: Option<Vec<String>>,
    /// Base64-encoded XDR ScVal value string.
    value: Option<String>,
    #[serde(rename = "pagingToken")]
    paging_token: Option<String>,
    id: Option<String>,
}

/// Sync all contracts (pool + ASP membership).
pub fn sync_all(db: &Database, cfg: &DeploymentConfig, network: &str) -> Result<()> {
    sync_contract(db, cfg, network, "pool", &cfg.pool)?;
    sync_contract(db, cfg, network, "asp_membership", &cfg.asp_membership)?;
    Ok(())
}

/// Sync events for a single contract.
fn sync_contract(
    db: &Database,
    _cfg: &DeploymentConfig,
    network: &str,
    contract_type: &str,
    contract_id: &str,
) -> Result<()> {
    let last_ledger = db.get_last_ledger(contract_type)?;
    let last_cursor = db.get_last_cursor(contract_type)?;

    // On first sync, determine a good start ledger within the RPC scan window.
    // Also handles the case where a stored last_ledger has fallen behind
    // the window (ledger retention is finite on public networks).
    let start = if last_ledger == 0 {
        // On first sync, find the valid scan window. Returns None for local networks
        // where ledger 1 is already valid.
        (stellar::get_oldest_ledger(contract_id, network)?).unwrap_or(1)
    } else {
        last_ledger
    };

    let mut cursor = last_cursor;
    let mut max_ledger = last_ledger;
    let mut adjusted_start = start;

    loop {
        let json_str = match stellar::fetch_events(
            contract_id,
            adjusted_start,
            cursor.as_deref(),
            network,
        ) {
            Ok(s) => s,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("No events") || msg.is_empty() {
                    break;
                }
                // If the start ledger fell behind the RPC window, adjust
                if msg.contains("ledger range")
                    && let Ok(Some(min)) = stellar::get_oldest_ledger(contract_id, network)
                {
                    adjusted_start = min;
                    continue;
                }
                return Err(e).context("Failed to fetch events");
            }
        };

        // The stellar CLI returns "No events" (exit 0) when no matching events
        // exist in the scan window.
        if json_str.is_empty() || json_str == "No events" {
            break;
        }

        // stellar events --output json returns either a JSON array or a stream of
        // pretty-printed JSON objects. Use serde's streaming deserializer to handle both.
        let events: Vec<StellarEvent> = if json_str.starts_with('[') {
            serde_json::from_str(&json_str)
                .context("Failed to parse events JSON array")?
        } else {
            let de = serde_json::Deserializer::from_str(&json_str);
            de.into_iter::<StellarEvent>()
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse events JSON stream")?
        };

        if events.is_empty() {
            break;
        }

        let mut last_token = None;
        for event in &events {
            if let Some(ledger) = event.ledger.filter(|&l| l > max_ledger) {
                max_ledger = ledger;
            }
            last_token = event.paging_token.as_deref().or(event.id.as_deref()).or(last_token);

            process_event(db, contract_type, event)?;
        }

        // Update cursor for next batch
        if let Some(token) = last_token {
            cursor = Some(token.to_string());
        }

        // If we got fewer than 1000 events, we've caught up
        if events.len() < 1000 {
            break;
        }
    }

    db.update_sync_metadata(contract_type, max_ledger, cursor.as_deref())?;
    Ok(())
}

/// Process a single event and store it in the database.
fn process_event(db: &Database, contract_type: &str, event: &StellarEvent) -> Result<()> {
    let topic_strings = match &event.topic {
        Some(t) if !t.is_empty() => t,
        _ => return Ok(()),
    };

    let ledger = event.ledger.unwrap_or(0);

    // Decode the first topic (event name) from base64 XDR
    let event_name = decode_xdr_symbol(&topic_strings[0]).unwrap_or_default();

    match contract_type {
        "pool" => process_pool_event(db, &event_name, topic_strings, &event.value, ledger),
        "asp_membership" => process_asp_event(db, &event_name, &event.value, ledger),
        _ => Ok(()),
    }
}

/// Process pool contract events.
fn process_pool_event(
    db: &Database,
    event_name: &str,
    topics: &[String],
    value: &Option<String>,
    ledger: u64,
) -> Result<()> {
    match event_name {
        // Soroban #[contractevent] auto-generates snake_case event names
        "new_commitment_event" => {
            // Topic[1] is the commitment (U256)
            let commitment_hex = topics
                .get(1)
                .and_then(|t| decode_xdr_u256_hex(t).ok())
                .context("Missing commitment in topic[1]")?;

            let val_xdr = value.as_deref().context("Missing value for commitment event")?;
            let val_map = decode_xdr_map(val_xdr)?;

            let index = val_map
                .get("index")
                .and_then(scval_to_u64)
                .context("Missing/invalid 'index' in commitment event")?;
            let encrypted_output = val_map
                .get("encrypted_output")
                .and_then(scval_to_bytes)
                .context("Missing/invalid 'encrypted_output' in commitment event")?;

            db.insert_pool_leaf(index, &commitment_hex, ledger)?;
            db.insert_encrypted_output(&commitment_hex, index, &encrypted_output, ledger)?;
        }
        "new_nullifier_event" => {
            let nullifier_hex = topics
                .get(1)
                .and_then(|t| decode_xdr_u256_hex(t).ok())
                .context("Missing nullifier in topic[1]")?;
            db.insert_nullifier(&nullifier_hex, ledger)?;
        }
        "public_key_event" => {
            // Topic[1] is the owner address (XDR Address)
            let address = topics
                .get(1)
                .and_then(|t| decode_xdr_address(t).ok())
                .unwrap_or_default();

            if let Some(val_xdr) = value.as_deref() {
                let val_map = decode_xdr_map(val_xdr)?;

                let note_key = val_map
                    .get("note_key")
                    .and_then(scval_to_hex)
                    .unwrap_or_default();
                let encryption_key = val_map
                    .get("encryption_key")
                    .and_then(scval_to_hex)
                    .unwrap_or_default();

                if !address.is_empty() && !note_key.is_empty() && !encryption_key.is_empty() {
                    db.upsert_public_key(&crate::db::RegisteredKey {
                        address,
                        note_key,
                        encryption_key,
                        ledger,
                    })?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Process ASP membership events.
fn process_asp_event(
    db: &Database,
    event_name: &str,
    value: &Option<String>,
    ledger: u64,
) -> Result<()> {
    // ASP membership uses #[contractevent(topics = ["LeafAdded"])]
    if event_name != "LeafAdded" {
        return Ok(());
    }

    let val_xdr = value.as_deref().context("Missing value for ASP event")?;
    let val_map = decode_xdr_map(val_xdr)?;

    let leaf = val_map
        .get("leaf")
        .and_then(scval_to_hex)
        .context("Missing/invalid 'leaf' in ASP event")?;
    let index = val_map
        .get("index")
        .and_then(scval_to_u64)
        .context("Missing/invalid 'index' in ASP event")?;

    db.insert_asp_leaf(index, &leaf, ledger)?;
    Ok(())
}

// ==================== XDR Decoding Helpers ====================

use xdr::Limits;

/// Decode a base64-encoded XDR ScVal as a Symbol string.
fn decode_xdr_symbol(b64: &str) -> Option<String> {
    let scval = ScVal::from_xdr_base64(b64, Limits::none()).ok()?;
    match scval {
        ScVal::Symbol(s) => Some(s.to_string()),
        _ => None,
    }
}

/// Decode a base64-encoded XDR ScVal containing a U256 to a big-endian hex string.
fn decode_xdr_u256_hex(b64: &str) -> Result<String> {
    let scval = ScVal::from_xdr_base64(b64, Limits::none()).context("Invalid XDR in topic")?;
    match scval {
        ScVal::U256(parts) => {
            // U256Parts: hi_hi, hi_lo, lo_hi, lo_lo (each u64, big-endian)
            let mut buf = [0u8; 32];
            buf[..8].copy_from_slice(&parts.hi_hi.to_be_bytes());
            buf[8..16].copy_from_slice(&parts.hi_lo.to_be_bytes());
            buf[16..24].copy_from_slice(&parts.lo_hi.to_be_bytes());
            buf[24..32].copy_from_slice(&parts.lo_lo.to_be_bytes());
            Ok(hex::encode(buf))
        }
        ScVal::Bytes(b) => Ok(hex::encode(b.as_slice())),
        _ => anyhow::bail!("Expected U256 or Bytes in topic, got {:?}", scval),
    }
}

/// Decode a base64-encoded XDR ScVal containing an Address to a G.../C... string.
fn decode_xdr_address(b64: &str) -> Result<String> {
    let scval =
        ScVal::from_xdr_base64(b64, Limits::none()).context("Invalid XDR in address topic")?;
    match scval {
        ScVal::Address(addr) => match addr {
            xdr::ScAddress::Account(acct) => {
                let xdr::PublicKey::PublicKeyTypeEd25519(key) = acct.0;
                Ok(stellar_strkey::ed25519::PublicKey(key.0).to_string())
            }
            xdr::ScAddress::Contract(hash) => {
                Ok(stellar_strkey::Contract(hash.0.into()).to_string())
            }
            _ => anyhow::bail!("Unsupported address type"),
        },
        _ => anyhow::bail!("Expected Address in topic, got {:?}", scval),
    }
}

/// Decode a base64-encoded XDR ScVal as a Map, returning entries by symbol key.
fn decode_xdr_map(b64: &str) -> Result<std::collections::HashMap<String, ScVal>> {
    let scval = ScVal::from_xdr_base64(b64, Limits::none()).context("Invalid XDR in value")?;

    let mut map = std::collections::HashMap::new();
    match scval {
        ScVal::Map(Some(entries)) => {
            for entry in entries.iter() {
                if let ScVal::Symbol(key) = &entry.key {
                    map.insert(key.to_string(), entry.val.clone());
                }
            }
        }
        _ => anyhow::bail!("Expected Map in event value, got {:?}", scval),
    }
    Ok(map)
}

/// Extract a u64 from a ScVal (U32 or U64).
fn scval_to_u64(val: &ScVal) -> Option<u64> {
    match val {
        ScVal::U32(n) => Some(u64::from(*n)),
        ScVal::U64(n) => Some(*n),
        _ => None,
    }
}

/// Extract bytes from a ScVal (Bytes or U256) as a big-endian hex string.
fn scval_to_hex(val: &ScVal) -> Option<String> {
    match val {
        ScVal::Bytes(b) => Some(hex::encode(b.as_slice())),
        ScVal::U256(parts) => {
            let mut buf = [0u8; 32];
            buf[..8].copy_from_slice(&parts.hi_hi.to_be_bytes());
            buf[8..16].copy_from_slice(&parts.hi_lo.to_be_bytes());
            buf[16..24].copy_from_slice(&parts.lo_hi.to_be_bytes());
            buf[24..32].copy_from_slice(&parts.lo_lo.to_be_bytes());
            Some(hex::encode(buf))
        }
        _ => None,
    }
}

/// Extract raw bytes from a ScVal (Bytes).
fn scval_to_bytes(val: &ScVal) -> Option<Vec<u8>> {
    match val {
        ScVal::Bytes(b) => Some(b.to_vec()),
        _ => None,
    }
}
