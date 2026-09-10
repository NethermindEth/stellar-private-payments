//! Measuring, extending, and restoring the lifetime of ledger entries.
//!
//! The RPC reports three states for a key: absent, archived, and live through
//! a given ledger. Everything the keeper submits is derived from that report.
//! A key the RPC does not return is never named in a transaction, a key it
//! reports archived is restored, and a key it reports live is extended once
//! its remaining lifetime falls to the threshold.

use crate::keys::{LEDGER_KEY_CHUNK, address};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::Duration,
};
use stellar_private_payments::chain::{BASE_FEE, Client, LocalSigner, apply_simulated_resources};
use stellar_xdr::{self as xdr, LedgerKey, Limits, ReadXdr, WriteXdr};

/// Attempts to read a transaction's outcome before giving up.
const CONFIRM_ATTEMPTS: u32 = 30;

/// Seconds between two attempts to read a transaction's outcome.
const CONFIRM_INTERVAL_SECS: u64 = 2;

/// Whether the ledger holds an entry, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifetime {
    /// The RPC returned no entry: the key was never written, or was deleted.
    Absent,
    /// The entry exists and has expired. Only a restore brings it back.
    ///
    /// The RPC returns such an entry with a live-until ledger of zero, because
    /// core does not record the ledger at which an entry was archived.
    Archived,
    /// The entry is live through the given ledger, inclusive.
    Live(u32),
}

/// A key and the state the RPC reported for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    /// The key the measurement was taken for.
    pub key: LedgerKey,
    /// The state of the entry under that key.
    pub lifetime: Lifetime,
}

/// The states of a set of keys, as of one ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// One entry per key measured, in the order the keys were given.
    pub entries: Vec<Measured>,
    /// The latest ledger the RPC had closed when it answered.
    ///
    /// Remaining lifetimes are counted from here, so the threshold is judged
    /// against the same ledger the entries were read at.
    pub latest_ledger: u32,
}

/// Reads the state of every key, in chunks the RPC accepts.
///
/// # Errors
///
/// Returns an error if a key cannot be encoded, the RPC refuses a chunk, or
/// the RPC returns an entry without a lifetime, which only a classic ledger
/// entry has and the keeper never asks for.
pub async fn measure(client: &Client, keys: &[LedgerKey]) -> Result<Measurement> {
    let mut reported = Vec::with_capacity(keys.len());
    let mut latest_ledger = 0;

    for chunk in keys.chunks(LEDGER_KEY_CHUNK) {
        let response = client
            .get_ledger_entries(chunk)
            .await
            .context("read ledger entries")?;
        let latest = u32::try_from(response.latest_ledger)
            .context("the RPC's latest ledger does not fit into u32")?;
        latest_ledger = latest_ledger.max(latest);

        let live_by_key: HashMap<_, _> = response
            .entries
            .unwrap_or_default()
            .into_iter()
            .map(|entry| (entry.key, entry.live_until_ledger_seq))
            .collect();
        for key in chunk {
            let encoded = key.to_xdr_base64(Limits::none())?;
            reported.push((key, live_by_key.get(&encoded).copied()));
        }
    }

    // Classify against one ledger for every chunk, so a key that expires
    // between two reads is archived here rather than live with nothing left.
    let entries = reported
        .into_iter()
        .map(|(key, live_until)| {
            Ok(Measured {
                key: key.clone(),
                lifetime: lifetime(live_until, latest_ledger)
                    .with_context(|| format!("entry {key:?}"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Measurement {
        entries,
        latest_ledger,
    })
}

/// Classifies one `getLedgerEntries` answer for a key.
///
/// `reported` is `None` when the response held no entry for the key, and
/// otherwise carries the entry's `liveUntilLedgerSeq` field. The RPC sets
/// that field to zero for an archived entry; an expiry ledger already behind
/// `latest` is read the same way, so a future RPC that reports the real
/// expiry ledger still classifies correctly.
fn lifetime(reported: Option<Option<u32>>, latest: u32) -> Result<Lifetime> {
    match reported {
        None => Ok(Lifetime::Absent),
        Some(Some(live_until)) if live_until >= latest => Ok(Lifetime::Live(live_until)),
        Some(Some(_)) => Ok(Lifetime::Archived),
        Some(None) => bail!("the entry has no lifetime, so it is not contract data or code"),
    }
}

/// Reads the network's maximum entry lifetime, in ledgers.
///
/// An `ExtendFootprintTtl` whose target exceeds this value less one is
/// malformed, and the simulation does not say so, so the keeper caps its
/// target against the value the network holds rather than assuming one.
///
/// # Errors
///
/// Returns an error if the RPC refuses the request or does not return the
/// state archival settings.
pub async fn max_entry_ttl(client: &Client) -> Result<u32> {
    let key = LedgerKey::ConfigSetting(xdr::LedgerKeyConfigSetting {
        config_setting_id: xdr::ConfigSettingId::StateArchival,
    });
    let response = client
        .get_ledger_entries(std::slice::from_ref(&key))
        .await
        .context("read the state archival settings")?;
    let entry = response
        .entries
        .unwrap_or_default()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("the RPC holds no state archival settings"))?;
    max_entry_ttl_from(&xdr::LedgerEntryData::from_xdr_base64(
        &entry.xdr,
        Limits::none(),
    )?)
}

/// Returns the lifetime an extension asks for.
///
/// `requested` is the operator's target, or `None` for the longest the network
/// allows. Either way the answer stays below `max_entry_ttl`, because an
/// `ExtendFootprintTtl` whose target is the maximum itself is malformed.
pub fn extend_target(requested: Option<u32>, max_entry_ttl: u32) -> u32 {
    let longest = max_entry_ttl.saturating_sub(1);
    requested.map_or(longest, |target| target.min(longest))
}

fn max_entry_ttl_from(data: &xdr::LedgerEntryData) -> Result<u32> {
    match data {
        xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) => {
            Ok(settings.max_entry_ttl)
        }
        other => bail!("expected the state archival settings, got {other:?}"),
    }
}

/// Returns the keys the RPC reported archived.
///
/// These are the only keys a restore may name. A key the RPC did not return
/// was never written, and naming it in a restore fails the simulation for
/// every other key in the batch.
pub fn archived(measurement: &Measurement) -> Vec<LedgerKey> {
    measurement
        .entries
        .iter()
        .filter(|m| m.lifetime == Lifetime::Archived)
        .map(|m| m.key.clone())
        .collect()
}

/// Returns the live keys whose remaining lifetime has fallen to `threshold`
/// or below.
///
/// The boundary is inclusive: a key with exactly `threshold` ledgers left is
/// extended, so a keeper running on a fixed interval never watches an entry
/// cross the line between two rounds.
pub fn below_threshold(measurement: &Measurement, threshold: u32) -> Vec<LedgerKey> {
    measurement
        .entries
        .iter()
        .filter(|m| match m.lifetime {
            Lifetime::Live(live_until) => {
                live_until.saturating_sub(measurement.latest_ledger) <= threshold
            }
            Lifetime::Absent | Lifetime::Archived => false,
        })
        .map(|m| m.key.clone())
        .collect()
}

/// Returns the shortest remaining lifetime of each contract's entries.
///
/// `extended` names the keys this round lifted to `extend_to`, which the
/// measurement was taken before. An archived key the round did not restore
/// reports zero, so the alert on the minimum stays raised until it is. Keys
/// that name no contract, such as uploaded wasm, are left out: their lifetime
/// is reported against the contracts that run them.
pub fn lowest_by_contract(
    measurement: &Measurement,
    extended: &[LedgerKey],
    extend_to: u32,
) -> BTreeMap<String, u32> {
    let extended: HashSet<&LedgerKey> = extended.iter().collect();
    let mut lowest: BTreeMap<String, u32> = BTreeMap::new();

    for entry in &measurement.entries {
        let LedgerKey::ContractData(data) = &entry.key else {
            continue;
        };
        let remaining = match entry.lifetime {
            _ if extended.contains(&entry.key) => extend_to,
            Lifetime::Live(live_until) => live_until.saturating_sub(measurement.latest_ledger),
            Lifetime::Archived => 0,
            Lifetime::Absent => continue,
        };
        lowest
            .entry(data.contract.to_string())
            .and_modify(|current| *current = (*current).min(remaining))
            .or_insert(remaining);
    }
    lowest
}

fn footprint(
    read_only: Vec<LedgerKey>,
    read_write: Vec<LedgerKey>,
) -> Result<xdr::LedgerFootprint> {
    Ok(xdr::LedgerFootprint {
        read_only: read_only.try_into()?,
        read_write: read_write.try_into()?,
    })
}

fn envelope(
    source: &str,
    sequence: i64,
    operation: xdr::OperationBody,
    footprint: xdr::LedgerFootprint,
) -> Result<xdr::TransactionEnvelope> {
    let xdr::ScAddress::Account(xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(key))) =
        address(source)?
    else {
        bail!("the keeper source must be an account address");
    };
    let account = xdr::MuxedAccount::Ed25519(key);
    let data = xdr::SorobanTransactionData {
        ext: xdr::SorobanTransactionDataExt::V0,
        resources: xdr::SorobanResources {
            footprint,
            instructions: 0,
            disk_read_bytes: 0,
            write_bytes: 0,
        },
        resource_fee: 0,
    };
    Ok(xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
        tx: xdr::Transaction {
            source_account: account,
            fee: BASE_FEE,
            seq_num: xdr::SequenceNumber(sequence),
            cond: xdr::Preconditions::None,
            memo: xdr::Memo::None,
            operations: vec![xdr::Operation {
                source_account: None,
                body: operation,
            }]
            .try_into()?,
            ext: xdr::TransactionExt::V1(data),
        },
        signatures: xdr::VecM::default(),
    }))
}

/// Builds the unsigned transaction that extends `keys` to `extend_to`.
///
/// The keys go in the read-only footprint, which is what
/// `ExtendFootprintTtl` reads.
///
/// # Errors
///
/// Returns an error if the source account is not a valid strkey, or the
/// footprint exceeds the XDR vector limit.
pub fn extend_envelope(
    source: &str,
    sequence: i64,
    keys: Vec<LedgerKey>,
    extend_to: u32,
) -> Result<xdr::TransactionEnvelope> {
    envelope(
        source,
        sequence,
        xdr::OperationBody::ExtendFootprintTtl(xdr::ExtendFootprintTtlOp {
            ext: xdr::ExtensionPoint::V0,
            extend_to,
        }),
        footprint(keys, Vec::new())?,
    )
}

/// Builds the unsigned transaction that restores `keys`.
///
/// The keys go in the read-write footprint, because a restore rewrites the
/// entries it brings back.
///
/// # Errors
///
/// Returns an error if the source account is not a valid strkey, or the
/// footprint exceeds the XDR vector limit.
pub fn restore_envelope(
    source: &str,
    sequence: i64,
    keys: Vec<LedgerKey>,
) -> Result<xdr::TransactionEnvelope> {
    envelope(
        source,
        sequence,
        xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp {
            ext: xdr::ExtensionPoint::V0,
        }),
        footprint(Vec::new(), keys)?,
    )
}

/// A lifetime transaction with the resources its simulation returned.
///
/// The simulation drops keys that need nothing from the footprint: a
/// never-written key from either operation, a live key from a restore, and a
/// key already above the target from an extend. `keys` is what remains, so
/// an empty list means the transaction would do nothing.
#[derive(Debug)]
pub struct Simulated {
    envelope: xdr::TransactionEnvelope,
    /// The keys the simulation kept in the footprint.
    pub keys: Vec<LedgerKey>,
    /// The keys the RPC requires restored before this transaction can run.
    ///
    /// Only an extend can carry these, and only when the RPC's simulation
    /// treats as archived a key its `getLedgerEntries` reported live.
    pub restore_first: Vec<LedgerKey>,
}

/// Simulates one lifetime transaction and applies the resources it returns.
///
/// # Errors
///
/// Returns an error if the RPC refuses the request or reports a simulation
/// error, which a restore naming a never-written key does.
pub async fn simulate(client: &Client, raw: xdr::TransactionEnvelope) -> Result<Simulated> {
    let simulation = client
        .simulate_transaction(&raw)
        .await
        .context("simulate lifetime transaction")?;
    simulation.ensure_success()?;
    simulated(
        raw,
        simulation.soroban_transaction_data()?,
        simulation.min_resource_fee_u64()?,
        simulation
            .restore_preamble
            .as_ref()
            .map(|preamble| preamble.transaction_data.as_str()),
    )
}

/// Assembles the simulated transaction from the parts of the RPC's answer.
///
/// `preamble_data` is the `transactionData` of the restore preamble, when the
/// simulation returned one.
fn simulated(
    raw: xdr::TransactionEnvelope,
    data: xdr::SorobanTransactionData,
    resource_fee: u64,
    preamble_data: Option<&str>,
) -> Result<Simulated> {
    let footprint = &data.resources.footprint;
    let keys = footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
        .cloned()
        .collect();
    let restore_first = match preamble_data {
        Some(encoded) => xdr::SorobanTransactionData::from_xdr_base64(encoded, Limits::none())
            .context("decode the restore preamble")?
            .resources
            .footprint
            .read_write
            .to_vec(),
        None => Vec::new(),
    };
    let envelope = apply_simulated_resources(&raw, data, resource_fee)?;
    Ok(Simulated {
        envelope,
        keys,
        restore_first,
    })
}

/// Signs, submits, and confirms a simulated lifetime transaction.
///
/// # Errors
///
/// Returns an error if the RPC rejects the submission, or the transaction
/// does not succeed within the confirmation window.
pub async fn send(
    client: &Client,
    signer: &LocalSigner,
    network_passphrase: &str,
    simulated: &Simulated,
) -> Result<String> {
    let signed = signer.sign_transaction(simulated.envelope.clone(), network_passphrase)?;
    let sent = client
        .send_transaction(&signed)
        .await
        .context("submit lifetime transaction")?;

    for _ in 0..CONFIRM_ATTEMPTS {
        tokio::time::sleep(Duration::from_secs(CONFIRM_INTERVAL_SECS)).await;
        let status = client.get_transaction(&sent.hash).await?.status;
        match status.as_str() {
            "SUCCESS" => return Ok(sent.hash),
            "NOT_FOUND" => continue,
            other => bail!("transaction {} ended {other}", sent.hash),
        }
    }
    bail!("transaction {} did not confirm", sent.hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

    fn key(byte: u8) -> LedgerKey {
        LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
            hash: xdr::Hash([byte; 32]),
        })
    }

    fn contract(byte: u8) -> xdr::ScAddress {
        xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([byte; 32])))
    }

    fn data(byte: u8, name: &str) -> LedgerKey {
        LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: contract(byte),
            key: xdr::ScVal::Symbol(xdr::ScSymbol::try_from(name).expect("symbol")),
            durability: xdr::ContractDataDurability::Persistent,
        })
    }

    fn resources(envelope: &xdr::TransactionEnvelope) -> xdr::SorobanResources {
        let xdr::TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a v1 envelope");
        };
        let xdr::TransactionExt::V1(data) = &v1.tx.ext else {
            panic!("expected soroban transaction data");
        };
        data.resources.clone()
    }

    fn operation(envelope: &xdr::TransactionEnvelope) -> xdr::OperationBody {
        let xdr::TransactionEnvelope::Tx(v1) = envelope else {
            panic!("expected a v1 envelope");
        };
        v1.tx
            .operations
            .first()
            .expect("one operation")
            .body
            .clone()
    }

    fn transaction_data(
        read_only: Vec<LedgerKey>,
        read_write: Vec<LedgerKey>,
    ) -> xdr::SorobanTransactionData {
        xdr::SorobanTransactionData {
            ext: xdr::SorobanTransactionDataExt::V0,
            resources: xdr::SorobanResources {
                footprint: footprint(read_only, read_write).expect("footprint"),
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 500,
        }
    }

    /// The shape `getLedgerEntries` answers with on the RPC the keeper runs
    /// against: an archived entry is returned with a live-until ledger of
    /// zero, and a never-written key is not returned at all.
    #[test]
    fn the_rpc_answer_classifies_into_absent_archived_and_live() {
        assert_eq!(lifetime(None, 1_000).expect("absent"), Lifetime::Absent);
        assert_eq!(
            lifetime(Some(Some(0)), 1_000).expect("archived"),
            Lifetime::Archived
        );
        assert_eq!(
            lifetime(Some(Some(1_000)), 1_000).expect("live"),
            Lifetime::Live(1_000)
        );
        assert_eq!(
            lifetime(Some(Some(4_707_343)), 1_000).expect("live"),
            Lifetime::Live(4_707_343)
        );
        // An expiry ledger the RPC has already passed is archived, whatever
        // placeholder the RPC uses.
        assert_eq!(
            lifetime(Some(Some(999)), 1_000).expect("expired"),
            Lifetime::Archived
        );
        assert!(lifetime(Some(None), 1_000).is_err());
    }

    /// The invariant every transaction rests on: a restore names only keys
    /// the RPC reported archived, an extend only keys it reported live, and a
    /// key it did not report appears in neither.
    #[test]
    fn only_reported_keys_are_restored_or_extended() {
        let measurement = Measurement {
            entries: vec![
                Measured {
                    key: key(1),
                    lifetime: Lifetime::Absent,
                },
                Measured {
                    key: key(2),
                    lifetime: Lifetime::Archived,
                },
                Measured {
                    key: key(3),
                    lifetime: Lifetime::Live(1_100),
                },
                Measured {
                    key: key(4),
                    lifetime: Lifetime::Live(1_101),
                },
            ],
            latest_ledger: 1_000,
        };

        assert_eq!(archived(&measurement), vec![key(2)]);
        assert_eq!(below_threshold(&measurement, 100), vec![key(3)]);
    }

    #[test]
    fn the_maximum_entry_lifetime_is_read_from_the_state_archival_settings() {
        let settings = xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(
            xdr::StateArchivalSettings {
                max_entry_ttl: 3_110_400,
                min_temporary_ttl: 16,
                min_persistent_ttl: 120_960,
                persistent_rent_rate_denominator: 1,
                temp_rent_rate_denominator: 1,
                max_entries_to_archive: 1,
                live_soroban_state_size_window_sample_size: 1,
                live_soroban_state_size_window_sample_period: 1,
                eviction_scan_size: 1,
                starting_eviction_scan_level: 1,
            },
        ));
        assert_eq!(max_entry_ttl_from(&settings).expect("settings"), 3_110_400);

        let other =
            xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::ContractMaxSizeBytes(1));
        assert!(max_entry_ttl_from(&other).is_err());
    }

    #[test]
    fn the_extend_target_stays_below_the_network_maximum() {
        assert_eq!(extend_target(None, 3_110_400), 3_110_399);
        assert_eq!(extend_target(Some(3_110_400), 3_110_400), 3_110_399);
        assert_eq!(extend_target(Some(100), 3_110_400), 100);
        assert_eq!(extend_target(Some(5), 0), 0);
    }

    #[test]
    fn the_extend_transaction_reads_its_keys_and_carries_the_target_ledger() {
        let keys = vec![key(1), key(2)];
        let envelope = extend_envelope(SOURCE, 7, keys.clone(), 3_110_400).expect("envelope");

        let footprint = resources(&envelope).footprint;
        assert_eq!(footprint.read_only.to_vec(), keys);
        assert!(footprint.read_write.is_empty());
        assert_eq!(
            operation(&envelope),
            xdr::OperationBody::ExtendFootprintTtl(xdr::ExtendFootprintTtlOp {
                ext: xdr::ExtensionPoint::V0,
                extend_to: 3_110_400,
            })
        );
    }

    #[test]
    fn the_restore_transaction_writes_its_keys() {
        let keys = vec![key(3), key(4)];
        let envelope = restore_envelope(SOURCE, 7, keys.clone()).expect("envelope");

        let footprint = resources(&envelope).footprint;
        assert_eq!(footprint.read_write.to_vec(), keys);
        assert!(footprint.read_only.is_empty());
        assert!(matches!(
            operation(&envelope),
            xdr::OperationBody::RestoreFootprint(_)
        ));
    }

    /// The simulation prunes the footprint to the keys that need the
    /// operation, and the keeper counts and extends only those.
    #[test]
    fn a_simulation_reports_the_keys_it_kept_and_the_fee_it_priced() {
        let raw =
            extend_envelope(SOURCE, 7, vec![key(1), key(2), key(3)], 3_110_400).expect("envelope");
        let simulated = simulated(
            raw,
            transaction_data(vec![key(1), key(3)], Vec::new()),
            500,
            None,
        )
        .expect("simulated");

        assert_eq!(simulated.keys, vec![key(1), key(3)]);
        assert!(simulated.restore_first.is_empty());
        let xdr::TransactionEnvelope::Tx(v1) = &simulated.envelope else {
            panic!("expected a v1 envelope");
        };
        // An extend pays the base fee above what the simulation priced.
        assert_eq!(v1.tx.fee, BASE_FEE + 500);
    }

    /// An extend whose simulation carries a restore preamble names a key the
    /// RPC's ledger-state answer called live and its simulation calls
    /// archived. The keys the preamble would restore are surfaced so the
    /// round can restore them first.
    #[test]
    fn a_restore_preamble_surfaces_the_keys_to_restore_first() {
        let raw = extend_envelope(SOURCE, 7, vec![key(1), key(2)], 3_110_400).expect("envelope");
        let preamble = transaction_data(Vec::new(), vec![key(2)])
            .to_xdr_base64(Limits::none())
            .expect("encode preamble");

        let simulated = simulated(
            raw,
            transaction_data(vec![key(1), key(2)], Vec::new()),
            500,
            Some(&preamble),
        )
        .expect("simulated");
        assert_eq!(simulated.restore_first, vec![key(2)]);
    }

    #[test]
    fn a_preamble_that_does_not_decode_is_an_error() {
        let raw = extend_envelope(SOURCE, 7, vec![key(1)], 3_110_400).expect("envelope");
        let result = simulated(
            raw,
            transaction_data(vec![key(1)], Vec::new()),
            500,
            Some("not xdr"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn the_lowest_remaining_lifetime_is_reported_for_each_contract() {
        let measurement = Measurement {
            entries: vec![
                Measured {
                    key: data(1, "a"),
                    lifetime: Lifetime::Live(1_500),
                },
                Measured {
                    key: data(1, "b"),
                    lifetime: Lifetime::Live(1_200),
                },
                Measured {
                    key: data(2, "a"),
                    lifetime: Lifetime::Live(1_900),
                },
                Measured {
                    key: data(3, "a"),
                    lifetime: Lifetime::Archived,
                },
                Measured {
                    key: data(4, "a"),
                    lifetime: Lifetime::Absent,
                },
                Measured {
                    key: key(7),
                    lifetime: Lifetime::Live(1_001),
                },
            ],
            latest_ledger: 1_000,
        };

        let lowest = lowest_by_contract(&measurement, &[], 3_110_400);
        assert_eq!(lowest.len(), 3);
        assert_eq!(lowest[&contract(1).to_string()], 200);
        assert_eq!(lowest[&contract(2).to_string()], 900);
        // An archived entry nobody restored has no lifetime left, and a key
        // that does not exist has nothing to report.
        assert_eq!(lowest[&contract(3).to_string()], 0);
        assert!(!lowest.contains_key(&contract(4).to_string()));

        // The round lifted the shortest-lived entry, so it reports the target.
        let lifted = lowest_by_contract(&measurement, &[data(1, "b")], 3_110_400);
        assert_eq!(lifted[&contract(1).to_string()], 1_500 - 1_000);
        // A restored and extended entry reports the target too.
        let restored = lowest_by_contract(&measurement, &[data(3, "a")], 3_110_400);
        assert_eq!(restored[&contract(3).to_string()], 3_110_400);
    }
}
