//! Building and reading the envelope of one admin contract call.
//!
//! An admin call is sourced by the contract's admin account, which may need
//! several signers. Each signer signs the same envelope, so it stays valid for
//! a day.

use anyhow::{Context, anyhow};
use stellar_xdr::{self as xdr, Limits, ReadXdr, WriteXdr};

use crate::{
    Error,
    chain::{
        BASE_FEE, PreparedSorobanTx, RpcClient, build_invoke_contract_tx_envelope,
        scval_to_address_string,
    },
};

/// Seconds an admin call stays valid.
const VALIDITY_SECS: u64 = 86_400;

/// Ledgers an entry an admin call reads must outlive its build: a day of
/// five-second ledgers, plus an hour.
const MIN_REMAINING_LEDGERS: u32 = 18_000;

/// An admin call, simulated and ready for its source's signers.
#[derive(Debug, Clone)]
pub struct UnsignedOperatorCall {
    /// Base64 `TransactionEnvelope` without signatures.
    pub envelope_xdr: String,
    pub call: OperatorCall,
}

/// What an admin call envelope does, as its signers read it.
#[derive(Debug, Clone, PartialEq)]
pub struct OperatorCall {
    pub source: String,
    pub sequence: i64,
    /// Most the source pays, in stroops.
    pub fee: u32,
    /// Unix seconds after which the network refuses the envelope.
    pub valid_until: u64,
    pub contract_id: String,
    pub method: String,
    pub args: Vec<xdr::ScVal>,
}

impl OperatorCall {
    /// The arguments as their signers read them: addresses as strkeys, lists
    /// in brackets, 256-bit integers as `0x` hex. Blocklist keys keep their
    /// input byte order.
    pub fn args_text(&self) -> Vec<String> {
        let order = if self.takes_note_keys() {
            ByteOrder::NoteKey
        } else {
            ByteOrder::BigEndian
        };
        self.args.iter().map(|arg| arg_text(arg, order)).collect()
    }

    /// Blocklist writes. The allowlist `insert_leaf` takes one argument.
    fn takes_note_keys(&self) -> bool {
        match self.method.as_str() {
            "insert_leaf" => self.args.len() == 2,
            "insert_leaves" | "delete_leaf" => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
enum ByteOrder {
    BigEndian,
    NoteKey,
}

fn arg_text(arg: &xdr::ScVal, order: ByteOrder) -> String {
    match arg {
        xdr::ScVal::Address(_) => {
            scval_to_address_string(arg).unwrap_or_else(|_| format!("{arg:?}"))
        }
        xdr::ScVal::U256(parts) => {
            let mut bytes = [0u8; 32];
            for (chunk, part) in
                bytes
                    .chunks_exact_mut(8)
                    .zip([parts.hi_hi, parts.hi_lo, parts.lo_hi, parts.lo_lo])
            {
                chunk.copy_from_slice(&part.to_be_bytes());
            }
            if let ByteOrder::NoteKey = order {
                bytes.reverse();
            }
            format!("0x{}", hex::encode(bytes))
        }
        xdr::ScVal::Vec(Some(items)) => {
            let items: Vec<String> = items.iter().map(|item| arg_text(item, order)).collect();
            format!("[{}]", items.join(", "))
        }
        other => format!("{other:?}"),
    }
}

/// Builds, simulates and checks the call of `method` on `contract_id`, sourced
/// by `source`.
///
/// # Errors
/// Returns [`Error::Refused`] when `source` is a contract, which cannot
/// source a transaction, [`Error::EntriesArchiveSoon`] when an entry the call
/// reads archives within a day, and an RPC or simulation error otherwise.
pub(crate) async fn build_call(
    rpc: &RpcClient,
    network_passphrase: &str,
    source: &str,
    contract_id: &str,
    method: &str,
    args: Vec<xdr::ScVal>,
) -> Result<UnsignedOperatorCall, Error> {
    if stellar_strkey::Contract::from_string(source).is_ok() {
        return Err(Error::Refused(format!(
            "the admin {source} is a contract; the operator API builds calls only for account \
             (G…) admins, so the contract has to authorize its own calls"
        )));
    }
    let account = rpc.get_account(source).await?;
    let sequence = xdr::SequenceNumber(
        account
            .seq_num
            .0
            .checked_add(1)
            .ok_or_else(|| anyhow!("account sequence number overflow"))?,
    );
    let mut raw = build_invoke_contract_tx_envelope(
        source,
        sequence,
        BASE_FEE,
        contract_id,
        method,
        args,
        Vec::new(),
    )?;
    let xdr::TransactionEnvelope::Tx(envelope) = &mut raw else {
        return Err(anyhow!("expected a v1 envelope").into());
    };
    envelope.tx.cond = xdr::Preconditions::Time(xdr::TimeBounds {
        min_time: xdr::TimePoint(0),
        max_time: xdr::TimePoint(unix_now()?.saturating_add(VALIDITY_SECS)),
    });

    let simulation = rpc.simulate_transaction(&raw).await?;
    let prepared = PreparedSorobanTx::from_simulation(&raw, &simulation)?;
    let envelope = xdr::TransactionEnvelope::from_xdr_base64(&prepared.tx_xdr, Limits::none())
        .context("decode assembled envelope")?;
    let call = describe(&envelope)?;
    refuse_short_lived_entries(rpc, network_passphrase, &envelope).await?;

    Ok(UnsignedOperatorCall {
        envelope_xdr: envelope
            .to_xdr_base64(Limits::none())
            .context("encode admin call envelope")?,
        call,
    })
}

/// Reads an admin call envelope, refusing anything its signers could not read
/// in full.
///
/// # Errors
/// Refuses a fee bump, an envelope without an expiring time bound or with any
/// other condition, more than one operation or one that is not a contract
/// call, and authorization beyond that call by the envelope's source.
pub fn describe(envelope: &xdr::TransactionEnvelope) -> Result<OperatorCall, Error> {
    let xdr::TransactionEnvelope::Tx(envelope) = envelope else {
        return Err(refusal(
            "the envelope is a fee bump or a v0 envelope, not an admin call",
        ));
    };
    let tx = &envelope.tx;
    // A minimum-sequence condition would keep a signed envelope valid past
    // later admin calls; a bound with no end never expires.
    let xdr::Preconditions::Time(bounds) = &tx.cond else {
        return Err(refusal(
            "the envelope carries conditions other than a time bound",
        ));
    };
    if bounds.max_time.0 == 0 {
        return Err(refusal("the envelope never expires"));
    }
    let ([operation], Some((invoke, call))) = (tx.operations.as_slice(), contract_call(tx)) else {
        return Err(refusal(
            "the envelope holds something other than one contract call",
        ));
    };
    if operation
        .source_account
        .as_ref()
        .is_some_and(|source| *source != tx.source_account)
    {
        return Err(refusal("the call has a source other than the envelope's"));
    }
    // The signatures cover every source-account entry, so another call's
    // entry would run undescribed.
    let described = |entry: &xdr::SorobanAuthorizationEntry| {
        entry.credentials == xdr::SorobanCredentials::SourceAccount
            && entry.root_invocation.function
                == xdr::SorobanAuthorizedFunction::ContractFn(call.clone())
            && entry.root_invocation.sub_invocations.is_empty()
    };
    if !invoke.auth.iter().all(described) {
        return Err(refusal(
            "the envelope authorizes something other than this call by its source",
        ));
    }

    Ok(OperatorCall {
        source: account_strkey(&tx.source_account),
        sequence: tx.seq_num.0,
        fee: tx.fee,
        valid_until: bounds.max_time.0,
        contract_id: scval_to_address_string(&xdr::ScVal::Address(call.contract_address.clone()))?,
        method: call.function_name.to_utf8_string_lossy(),
        args: call.args.to_vec(),
    })
}

fn contract_call(
    tx: &xdr::Transaction,
) -> Option<(&xdr::InvokeHostFunctionOp, &xdr::InvokeContractArgs)> {
    let xdr::OperationBody::InvokeHostFunction(invoke) = &tx.operations.first()?.body else {
        return None;
    };
    match &invoke.host_function {
        xdr::HostFunction::InvokeContract(call) => Some((invoke, call)),
        _ => None,
    }
}

fn refusal(reason: &str) -> Error {
    Error::Refused(format!("refusing the admin call envelope: {reason}"))
}

pub(crate) fn account_strkey(account: &xdr::MuxedAccount) -> String {
    let key = match account {
        xdr::MuxedAccount::Ed25519(key) => key.0,
        xdr::MuxedAccount::MuxedEd25519(muxed) => muxed.ed25519.0,
    };
    stellar_strkey::ed25519::PublicKey(key)
        .to_string()
        .as_str()
        .to_string()
}

pub(super) fn unix_now() -> Result<u64, Error> {
    Ok(web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

/// Persistent entries the envelope reads and does not restore itself. An
/// entry that archives between build and send fails the call.
fn live_footprint_keys(envelope: &xdr::TransactionEnvelope) -> Vec<xdr::LedgerKey> {
    let xdr::TransactionEnvelope::Tx(envelope) = envelope else {
        return Vec::new();
    };
    let xdr::TransactionExt::V1(data) = &envelope.tx.ext else {
        return Vec::new();
    };
    let footprint = &data.resources.footprint;
    let restored: Vec<&xdr::LedgerKey> = match &data.ext {
        xdr::SorobanTransactionDataExt::V1(ext) => ext
            .archived_soroban_entries
            .iter()
            .filter_map(|&index| footprint.read_write.get(usize::try_from(index).ok()?))
            .collect(),
        xdr::SorobanTransactionDataExt::V0 => Vec::new(),
    };
    footprint
        .read_only
        .iter()
        .chain(footprint.read_write.iter())
        .filter(|key| !restored.contains(key))
        .filter(|key| match key {
            xdr::LedgerKey::ContractCode(_) => true,
            xdr::LedgerKey::ContractData(data) => {
                data.durability == xdr::ContractDataDurability::Persistent
            }
            _ => false,
        })
        .cloned()
        .collect()
}

async fn refuse_short_lived_entries(
    rpc: &RpcClient,
    network_passphrase: &str,
    envelope: &xdr::TransactionEnvelope,
) -> Result<(), Error> {
    let keys = live_footprint_keys(envelope);
    if keys.is_empty() {
        return Ok(());
    }
    let response = rpc.get_ledger_entries(&keys).await?;
    let latest = u32::try_from(response.latest_ledger).unwrap_or(u32::MAX);
    let short: Vec<String> = response
        .entries
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| {
            entry
                .live_until_ledger
                .is_some_and(|live_until| live_until < latest.saturating_add(MIN_REMAINING_LEDGERS))
        })
        .map(|entry| entry.key)
        .collect();
    if short.is_empty() {
        return Ok(());
    }
    let ledgers = max_entry_ttl(rpc).await?.saturating_sub(1);
    let extend_commands = short
        .iter()
        .map(|key| {
            let key = xdr::LedgerKey::from_xdr_base64(key, Limits::none())
                .context("decode ledger key")?;
            extend_command(&key, ledgers, rpc.base_url(), network_passphrase)
        })
        .collect::<Result<_, Error>>()?;
    Err(Error::EntriesArchiveSoon { extend_commands })
}

/// The network's `max_entry_ttl`: an entry lives at most that many ledgers,
/// counting the current one.
async fn max_entry_ttl(rpc: &RpcClient) -> Result<u32, Error> {
    let key = xdr::LedgerKey::ConfigSetting(xdr::LedgerKeyConfigSetting {
        config_setting_id: xdr::ConfigSettingId::StateArchival,
    });
    let response = rpc.get_ledger_entries(&[key]).await?;
    let entry = response
        .entries
        .unwrap_or_default()
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("the RPC returned no state archival settings"))?;
    match xdr::LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())
        .context("decode state archival settings")?
    {
        xdr::LedgerEntryData::ConfigSetting(xdr::ConfigSettingEntry::StateArchival(settings)) => {
            Ok(settings.max_entry_ttl)
        }
        _ => Err(anyhow!("expected state archival settings").into()),
    }
}

/// The Stellar CLI command that extends the entry under `key` to live
/// `ledgers` ledgers past the current one. `ACCOUNT` stands for the payer.
fn extend_command(
    key: &xdr::LedgerKey,
    ledgers: u32,
    rpc_url: &str,
    network_passphrase: &str,
) -> Result<String, Error> {
    let target = match key {
        xdr::LedgerKey::ContractCode(code) => format!("--wasm-hash {}", hex::encode(code.hash.0)),
        xdr::LedgerKey::ContractData(data) => {
            let id = scval_to_address_string(&xdr::ScVal::Address(data.contract.clone()))?;
            match &data.key {
                xdr::ScVal::LedgerKeyContractInstance => format!("--id {id}"),
                other => format!(
                    "--id {id} --key-xdr {}",
                    other
                        .to_xdr_base64(Limits::none())
                        .context("encode ledger key")?
                ),
            }
        }
        _ => return Err(anyhow!("only contract code and data entries can be extended").into()),
    };
    Ok(format!(
        "stellar contract extend {target} --ledgers-to-extend {ledgers} --source-account ACCOUNT \
         --rpc-url {} --network-passphrase {}",
        shell_quote(rpc_url),
        shell_quote(network_passphrase)
    ))
}

/// Quotes `value` as one POSIX shell word.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    const SOURCE: [u8; 32] = [7; 32];
    const CONTRACT: [u8; 32] = [9; 32];

    fn call_args() -> xdr::InvokeContractArgs {
        xdr::InvokeContractArgs {
            contract_address: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(CONTRACT))),
            function_name: xdr::ScSymbol::try_from("pause_deposits").expect("symbol"),
            args: xdr::VecM::default(),
        }
    }

    fn source_auth() -> xdr::SorobanAuthorizationEntry {
        xdr::SorobanAuthorizationEntry {
            credentials: xdr::SorobanCredentials::SourceAccount,
            root_invocation: xdr::SorobanAuthorizedInvocation {
                function: xdr::SorobanAuthorizedFunction::ContractFn(call_args()),
                sub_invocations: xdr::VecM::default(),
            },
        }
    }

    fn operation(auth: Vec<xdr::SorobanAuthorizationEntry>) -> xdr::Operation {
        xdr::Operation {
            source_account: None,
            body: xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
                host_function: xdr::HostFunction::InvokeContract(call_args()),
                auth: auth.try_into().expect("auth"),
            }),
        }
    }

    fn soroban_data(
        footprint: xdr::LedgerFootprint,
        archived: Vec<u32>,
    ) -> xdr::SorobanTransactionData {
        xdr::SorobanTransactionData {
            ext: if archived.is_empty() {
                xdr::SorobanTransactionDataExt::V0
            } else {
                xdr::SorobanTransactionDataExt::V1(xdr::SorobanResourcesExtV0 {
                    archived_soroban_entries: archived.try_into().expect("indices"),
                })
            },
            resources: xdr::SorobanResources {
                footprint,
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 500,
        }
    }

    pub(in crate::operator) fn envelope() -> xdr::TransactionEnvelope {
        xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
            tx: xdr::Transaction {
                source_account: xdr::MuxedAccount::Ed25519(xdr::Uint256(SOURCE)),
                fee: 1_000,
                seq_num: xdr::SequenceNumber(42),
                cond: xdr::Preconditions::Time(xdr::TimeBounds {
                    min_time: xdr::TimePoint(0),
                    max_time: xdr::TimePoint(1_000_000),
                }),
                memo: xdr::Memo::None,
                operations: vec![operation(vec![source_auth()])]
                    .try_into()
                    .expect("ops"),
                ext: xdr::TransactionExt::V1(soroban_data(
                    xdr::LedgerFootprint {
                        read_only: xdr::VecM::default(),
                        read_write: xdr::VecM::default(),
                    },
                    Vec::new(),
                )),
            },
            signatures: xdr::VecM::default(),
        })
    }

    fn with_tx(edit: impl FnOnce(&mut xdr::Transaction)) -> xdr::TransactionEnvelope {
        let mut envelope = envelope();
        let xdr::TransactionEnvelope::Tx(v1) = &mut envelope else {
            unreachable!()
        };
        edit(&mut v1.tx);
        envelope
    }

    fn refusal_of(envelope: &xdr::TransactionEnvelope) -> String {
        match describe(envelope) {
            Err(Error::Refused(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn data_key(byte: u8, durability: xdr::ContractDataDurability) -> xdr::LedgerKey {
        xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([byte; 32]))),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability,
        })
    }

    #[test]
    fn describe_reads_the_call_its_signers_sign() {
        let call = describe(&envelope()).expect("a plain admin call");
        assert_eq!(
            call,
            OperatorCall {
                source: stellar_strkey::ed25519::PublicKey(SOURCE)
                    .to_string()
                    .as_str()
                    .to_string(),
                sequence: 42,
                fee: 1_000,
                valid_until: 1_000_000,
                contract_id: stellar_strkey::Contract(CONTRACT)
                    .to_string()
                    .as_str()
                    .to_string(),
                method: "pause_deposits".to_string(),
                args: Vec::new(),
            }
        );
    }

    #[test]
    fn args_text_reads_addresses_integers_and_lists() {
        let mut call = describe(&envelope()).expect("call");
        let key = xdr::ScVal::U256(xdr::UInt256Parts {
            hi_hi: 0,
            hi_lo: 0,
            lo_hi: 0,
            lo_lo: 0x2a,
        });
        call.args = vec![
            xdr::ScVal::Address(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
                CONTRACT,
            )))),
            xdr::ScVal::Vec(Some(vec![key.clone(), key].try_into().expect("pair"))),
        ];
        let forty_two = format!("0x{:064x}", 0x2a);
        assert_eq!(
            call.args_text(),
            vec![
                stellar_strkey::Contract(CONTRACT)
                    .to_string()
                    .as_str()
                    .to_string(),
                format!("[{forty_two}, {forty_two}]"),
            ]
        );
    }

    #[test]
    fn describe_refuses_an_envelope_that_never_expires() {
        let envelope = with_tx(|tx| tx.cond = xdr::Preconditions::None);
        assert!(refusal_of(&envelope).contains("other than a time bound"));
        let envelope = with_tx(|tx| {
            tx.cond = xdr::Preconditions::Time(xdr::TimeBounds {
                min_time: xdr::TimePoint(0),
                max_time: xdr::TimePoint(0),
            })
        });
        assert!(refusal_of(&envelope).contains("never expires"));
    }

    #[test]
    fn describe_refuses_a_second_operation() {
        let envelope = with_tx(|tx| {
            tx.operations = vec![operation(vec![]), operation(vec![])]
                .try_into()
                .expect("ops")
        });
        assert!(refusal_of(&envelope).contains("one contract call"));
    }

    #[test]
    fn describe_refuses_an_operation_sourced_by_another_account() {
        let envelope = with_tx(|tx| {
            let mut op = operation(vec![source_auth()]);
            op.source_account = Some(xdr::MuxedAccount::Ed25519(xdr::Uint256([1; 32])));
            tx.operations = vec![op].try_into().expect("ops");
        });
        assert!(refusal_of(&envelope).contains("source other than"));
    }

    #[test]
    fn describe_refuses_authorization_beyond_the_call() {
        let mut nested = source_auth();
        nested.root_invocation.sub_invocations = vec![source_auth().root_invocation]
            .try_into()
            .expect("sub invocations");
        let mut other_account = source_auth();
        other_account.credentials =
            xdr::SorobanCredentials::Address(xdr::SorobanAddressCredentials {
                address: xdr::ScAddress::Account(xdr::AccountId(
                    xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256([1; 32])),
                )),
                nonce: 0,
                signature_expiration_ledger: 0,
                signature: xdr::ScVal::Void,
            });
        // Covered by the source's signatures like the call itself, so a
        // `pause_deposits` envelope would move the admin's tokens unseen.
        let mut transfer = source_auth();
        transfer.root_invocation.function =
            xdr::SorobanAuthorizedFunction::ContractFn(xdr::InvokeContractArgs {
                contract_address: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash([9; 32]))),
                function_name: xdr::ScSymbol::try_from("transfer").expect("symbol"),
                args: xdr::VecM::default(),
            });
        for entry in [nested, other_account, transfer] {
            let envelope =
                with_tx(|tx| tx.operations = vec![operation(vec![entry])].try_into().expect("ops"));
            assert!(refusal_of(&envelope).contains("authorizes something other"));
        }
    }

    #[test]
    fn live_footprint_keys_skip_restored_and_temporary_entries() {
        let persistent = data_key(1, xdr::ContractDataDurability::Persistent);
        let restored = data_key(2, xdr::ContractDataDurability::Persistent);
        let temporary = data_key(3, xdr::ContractDataDurability::Temporary);
        let code = xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
            hash: xdr::Hash([4; 32]),
        });
        let envelope = with_tx(|tx| {
            tx.ext = xdr::TransactionExt::V1(soroban_data(
                xdr::LedgerFootprint {
                    read_only: vec![code.clone(), temporary.clone()]
                        .try_into()
                        .expect("ro"),
                    read_write: vec![persistent.clone(), restored.clone()]
                        .try_into()
                        .expect("rw"),
                },
                vec![1],
            ))
        });
        assert_eq!(live_footprint_keys(&envelope), vec![code, persistent]);
    }

    #[test]
    fn extend_commands_name_the_entry() {
        let instance = data_key(1, xdr::ContractDataDurability::Persistent);
        let command = extend_command(&instance, 99, "https://rpc.test", "net").expect("command");
        assert_eq!(
            command,
            format!(
                "stellar contract extend --id {} --ledgers-to-extend 99 --source-account ACCOUNT \
                 --rpc-url 'https://rpc.test' --network-passphrase 'net'",
                stellar_strkey::Contract([1; 32])
            )
        );
        let code = xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
            hash: xdr::Hash([4; 32]),
        });
        let command = extend_command(&code, 99, "https://rpc.test", "net").expect("command");
        assert!(command.contains(&format!("--wasm-hash {}", "04".repeat(32))));
    }

    #[test]
    fn extend_commands_quote_the_network() {
        let code = xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
            hash: xdr::Hash([4; 32]),
        });
        let command =
            extend_command(&code, 99, "https://rpc.test/?key=a&b=c", "it's").expect("command");
        assert!(
            command.ends_with(
                r"--rpc-url 'https://rpc.test/?key=a&b=c' --network-passphrase 'it'\''s'"
            ),
            "{command}"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn refuses_a_contract_source_before_reading_the_chain() {
        let rpc = RpcClient::new("http://127.0.0.1:9").expect("rpc");
        let contract = stellar_strkey::Contract(CONTRACT).to_string();
        let result = build_call(
            &rpc,
            "passphrase",
            &contract,
            &contract,
            "accept_admin",
            Vec::new(),
        )
        .await;
        assert!(
            matches!(result, Err(Error::Refused(message)) if message.contains("is a contract"))
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(in crate::operator) fn rpc_answer(result: serde_json::Value) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }))
    }

    /// Matches a simulation of a call to `method`.
    #[cfg(not(target_arch = "wasm32"))]
    pub(in crate::operator) fn simulating(
        method: &'static str,
    ) -> impl Fn(&wiremock::Request) -> bool + Send + Sync {
        move |request| {
            let Ok(body) = serde_json::from_slice::<serde_json::Value>(&request.body) else {
                return false;
            };
            let Some(tx) = body["params"]["transaction"].as_str() else {
                return false;
            };
            let Ok(envelope) = xdr::TransactionEnvelope::from_xdr_base64(tx, Limits::none()) else {
                return false;
            };
            let xdr::TransactionEnvelope::Tx(envelope) = envelope else {
                return false;
            };
            contract_call(&envelope.tx)
                .is_some_and(|(_, call)| call.function_name.0.as_slice() == method.as_bytes())
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod chain {
        use serde_json::json;
        use wiremock::{Mock, MockServer, matchers::body_partial_json};

        use super::*;

        pub const LATEST: u32 = 1_000;
        pub const MAX_ENTRY_TTL: u32 = 3_110_400;
        pub const PASSPHRASE: &str = "Test SDF Network ; September 2015";

        fn b64(value: &impl WriteXdr) -> String {
            value.to_xdr_base64(Limits::none()).expect("xdr")
        }

        async fn ledger_entries(
            server: &MockServer,
            keys: &[xdr::LedgerKey],
            entries: serde_json::Value,
        ) {
            let keys: Vec<String> = keys.iter().map(b64).collect();
            Mock::given(body_partial_json(
                json!({ "method": "getLedgerEntries", "params": { "keys": keys } }),
            ))
            .respond_with(rpc_answer(
                json!({ "latestLedger": LATEST, "entries": entries }),
            ))
            .mount(server)
            .await;
        }

        /// A chain where the source's sequence is 41 and `pause_deposits` on
        /// the contract reads `entries`, each live until the given ledger.
        pub async fn serve(entries: &[(xdr::LedgerKey, u32)]) -> MockServer {
            let server = MockServer::start().await;
            let account_id =
                xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(SOURCE)));
            let account = xdr::LedgerEntryData::Account(xdr::AccountEntry {
                account_id: account_id.clone(),
                seq_num: xdr::SequenceNumber(41),
                ..Default::default()
            });
            let account_key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount { account_id });
            let found = json!([{ "key": b64(&account_key), "xdr": b64(&account), "lastModifiedLedgerSeq": 0 }]);
            ledger_entries(&server, &[account_key], found).await;

            let keys: Vec<xdr::LedgerKey> = entries.iter().map(|(key, _)| key.clone()).collect();
            let footprint = xdr::LedgerFootprint {
                read_only: keys.clone().try_into().expect("keys"),
                read_write: xdr::VecM::default(),
            };
            Mock::given(simulating("pause_deposits"))
                .respond_with(rpc_answer(json!({
                    "latestLedger": LATEST,
                    "minResourceFee": "500",
                    "transactionData": b64(&soroban_data(footprint, Vec::new())),
                    "results": [{ "auth": [b64(&source_auth())], "xdr": b64(&xdr::ScVal::Void) }],
                })))
                .mount(&server)
                .await;
            if entries.is_empty() {
                return server;
            }

            // The check reads only the keys and TTLs.
            let found = entries
                .iter()
                .map(|(key, live_until)| {
                    json!({ "key": b64(key), "xdr": "", "lastModifiedLedgerSeq": 0, "liveUntilLedgerSeq": live_until })
                })
                .collect();
            ledger_entries(&server, &keys, found).await;
            let settings = xdr::LedgerKey::ConfigSetting(xdr::LedgerKeyConfigSetting {
                config_setting_id: xdr::ConfigSettingId::StateArchival,
            });
            let archival = xdr::LedgerEntryData::ConfigSetting(
                xdr::ConfigSettingEntry::StateArchival(xdr::StateArchivalSettings {
                    max_entry_ttl: MAX_ENTRY_TTL,
                    ..Default::default()
                }),
            );
            let found = json!([{ "key": b64(&settings), "xdr": b64(&archival), "lastModifiedLedgerSeq": 0 }]);
            ledger_entries(&server, &[settings], found).await;
            server
        }

        pub async fn build(
            server: &MockServer,
        ) -> (RpcClient, Result<UnsignedOperatorCall, Error>) {
            let rpc = RpcClient::new(&server.uri()).expect("rpc");
            let source = stellar_strkey::ed25519::PublicKey(SOURCE).to_string();
            let contract = stellar_strkey::Contract(CONTRACT).to_string();
            let result = build_call(
                &rpc,
                PASSPHRASE,
                &source,
                &contract,
                "pause_deposits",
                Vec::new(),
            )
            .await;
            (rpc, result)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn build_call_bounds_and_describes_the_call() {
        let server = chain::serve(&[]).await;
        let before = unix_now().expect("now");
        let (_, result) = chain::build(&server).await;
        let after = unix_now().expect("now");
        let unsigned = result.expect("call");

        let envelope =
            xdr::TransactionEnvelope::from_xdr_base64(&unsigned.envelope_xdr, Limits::none())
                .expect("envelope");
        let call = describe(&envelope).expect("describe");
        assert_eq!(call, unsigned.call);
        assert_eq!(call.sequence, 42);
        assert!((before + VALIDITY_SECS..=after + VALIDITY_SECS).contains(&call.valid_until));
        // The simulation asks a resource fee of 500 for an empty footprint.
        assert_eq!(call.fee, BASE_FEE + 500);
        let xdr::TransactionEnvelope::Tx(v1) = &envelope else {
            unreachable!()
        };
        let xdr::TransactionExt::V1(data) = &v1.tx.ext else {
            panic!("expected Soroban data")
        };
        assert_eq!(data.resource_fee, 500);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn build_call_refuses_an_entry_that_archives_within_a_day() {
        use chain::*;

        let lasts = data_key(1, xdr::ContractDataDurability::Persistent);
        let archives = data_key(2, xdr::ContractDataDurability::Persistent);
        let server = serve(&[
            (lasts, LATEST + MIN_REMAINING_LEDGERS),
            (archives.clone(), LATEST + MIN_REMAINING_LEDGERS - 1),
        ])
        .await;
        let (rpc, result) = build(&server).await;
        let Err(Error::EntriesArchiveSoon { extend_commands }) = result else {
            panic!("expected EntriesArchiveSoon, got {result:?}")
        };
        let command = extend_command(&archives, MAX_ENTRY_TTL - 1, rpc.base_url(), PASSPHRASE)
            .expect("command");
        assert_eq!(extend_commands, vec![command]);
    }
}
