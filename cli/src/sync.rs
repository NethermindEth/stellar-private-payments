//! Event fetching and incremental sync.
//!
//! Uses `stellar events --output json` to fetch contract events and stores
//! them in the SQLite database.

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::config::DeploymentConfig;
use crate::db::Database;
use crate::stellar;

/// A single event from `stellar events --output json`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StellarEvent {
    #[serde(rename = "type")]
    event_type: Option<String>,
    ledger: Option<u64>,
    #[serde(rename = "contractId")]
    contract_id: Option<String>,
    topic: Option<Vec<serde_json::Value>>,
    value: Option<serde_json::Value>,
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

    // Start from ledger 1 if never synced, else from last known ledger
    let start = if last_ledger == 0 { 1 } else { last_ledger };

    let mut cursor = last_cursor;
    let mut max_ledger = last_ledger;

    loop {
        let json_str = match stellar::fetch_events(
            contract_id,
            start,
            cursor.as_deref(),
            network,
        ) {
            Ok(s) => s,
            Err(e) => {
                // If events command fails (e.g., no events), just break
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("No events") || msg.is_empty() {
                    break;
                }
                return Err(e).context("Failed to fetch events");
            }
        };

        if json_str.is_empty() {
            break;
        }

        // stellar events --output json can return a JSON array or individual objects
        let events: Vec<StellarEvent> = if json_str.starts_with('[') {
            serde_json::from_str(&json_str)
                .context("Failed to parse events JSON array")?
        } else {
            // Try parsing as newline-delimited JSON
            json_str
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(serde_json::from_str)
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse events JSON lines")?
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
    let topics = match &event.topic {
        Some(t) => t,
        None => return Ok(()),
    };

    let ledger = event.ledger.unwrap_or(0);

    // Extract the event name from topics
    let event_name = topics
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match contract_type {
        "pool" => process_pool_event(db, event_name, topics, &event.value, ledger),
        "asp_membership" => process_asp_event(db, event_name, &event.value, ledger),
        _ => Ok(()),
    }
}

/// Process pool contract events.
fn process_pool_event(
    db: &Database,
    event_name: &str,
    topics: &[serde_json::Value],
    value: &Option<serde_json::Value>,
    ledger: u64,
) -> Result<()> {
    match event_name {
        "NewCommitmentEvent" | "new_commitment" => {
            // Topic[1] is the commitment (U256)
            let commitment = extract_u256_from_topic(topics.get(1))?;
            let val = value.as_ref().context("Missing value for commitment event")?;

            // Value contains {index, encrypted_output}
            let index = extract_u64_field(val, "index")
                .or_else(|_| extract_u64_field(val, "0"))?;
            let encrypted_output = extract_bytes_field(val, "encrypted_output")
                .or_else(|_| extract_bytes_field(val, "1"))?;

            db.insert_pool_leaf(index, &commitment, ledger)?;
            db.insert_encrypted_output(&commitment, index, &encrypted_output, ledger)?;
        }
        "NewNullifierEvent" | "new_nullifier" => {
            let nullifier = extract_u256_from_topic(topics.get(1))?;
            db.insert_nullifier(&nullifier, ledger)?;
        }
        "PublicKeyEvent" | "public_key" => {
            // Topic[1] is the owner address
            let address = topics
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            if let Some(val) = value {
                let note_key = extract_hex_field(val, "note_key")
                    .or_else(|_| extract_hex_field(val, "1"))
                    .unwrap_or_default();
                let encryption_key = extract_hex_field(val, "encryption_key")
                    .or_else(|_| extract_hex_field(val, "0"))
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
    value: &Option<serde_json::Value>,
    ledger: u64,
) -> Result<()> {
    if event_name != "LeafAdded" && event_name != "leaf_added" {
        return Ok(());
    }

    let val = value.as_ref().context("Missing value for ASP event")?;

    let leaf = extract_hex_field(val, "leaf")
        .or_else(|_| extract_hex_field(val, "0"))?;
    let index = extract_u64_field(val, "index")
        .or_else(|_| extract_u64_field(val, "1"))?;

    db.insert_asp_leaf(index, &leaf, ledger)?;
    Ok(())
}

// ==================== Helpers ====================

/// Extract a U256 hex string from a topic value.
fn extract_u256_from_topic(val: Option<&serde_json::Value>) -> Result<String> {
    let v = val.context("Missing topic value")?;
    // Could be a string directly, or a nested structure
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    // Try as object with bytes field
    if let Some(s) = v.as_object().and_then(|obj| obj.get("bytes")).and_then(|b| b.as_str()) {
        return Ok(s.to_string());
    }
    // Fallback: serialize as string
    Ok(v.to_string())
}

/// Extract a u64 from a JSON value field.
fn extract_u64_field(val: &serde_json::Value, field: &str) -> Result<u64> {
    let v = val
        .get(field)
        .context(format!("Missing field '{field}'"))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        return s.parse().context(format!("Invalid u64 in field '{field}'"));
    }
    anyhow::bail!("Cannot parse field '{field}' as u64")
}

/// Extract bytes from a JSON value field (hex-encoded).
fn extract_bytes_field(val: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let v = val
        .get(field)
        .context(format!("Missing field '{field}'"))?;
    if let Some(s) = v.as_str() {
        let s = s.strip_prefix("0x").unwrap_or(s);
        return hex::decode(s).context(format!("Invalid hex in field '{field}'"));
    }
    // Could be an array of numbers
    if let Some(arr) = v.as_array() {
        let bytes: Result<Vec<u8>, _> = arr
            .iter()
            .map(|x| {
                x.as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .context("Invalid byte value")
            })
            .collect();
        return bytes;
    }
    anyhow::bail!("Cannot parse field '{field}' as bytes")
}

/// Extract a hex string from a JSON value field.
fn extract_hex_field(val: &serde_json::Value, field: &str) -> Result<String> {
    let v = val
        .get(field)
        .context(format!("Missing field '{field}'"))?;
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    anyhow::bail!("Cannot parse field '{field}' as hex string")
}
