// many parts are taken from https://github.com/stellar/rs-stellar-rpc-client/blob/main/src/lib.rs
// to make it wasm-compatible

use crate::chain::conversions::instance_storage_entries;
use http::{Uri, uri::Authority};
use serde::{Deserialize, Serialize};
use serde_aux::prelude::deserialize_default_from_null;
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};
use stellar_xdr::{
    self as xdr, AccountEntry, AccountId, ContractId, Error as XdrError, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, Uint256, WriteXdr,
};

use super::{soroban_encode::BASE_FEE, tx_assemble::build_invoke_contract_tx_envelope};

// https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getEvents
const MAX_CONTRACT_IDS_PER_FILTER: usize = 5;
const MAX_FILTERS_PER_REQUEST: usize = 5;
const MAX_FILTER_CONTRACT_IDS: usize = MAX_CONTRACT_IDS_PER_FILTER * MAX_FILTERS_PER_REQUEST;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    InvalidAddress(#[from] stellar_strkey::DecodeError),
    #[error("network error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("jsonrpc error: {code} - {message}")]
    JsonRpc { code: i64, message: String },
    #[error("bootnode retention handoff - continue on main RPC from ledger {from_ledger}")]
    RetentionHandoff { from_ledger: u32 },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(#[from] http::uri::InvalidUri),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrlFromUriParts(#[from] http::uri::InvalidUriParts),
    #[error("json decoding error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0} not found: {1}")]
    NotFound(&'static str, String),
    #[error("Duplicate key found in contract data: {0}")]
    DuplicateContractKey(String),
    #[error("Unexpected ScVal: {0:?}")]
    UnexpectedScVal(String),
    #[error("RPC sync gap - the oldest ledger is: {0:?}")]
    RpcSyncGap(u32),
    #[error("local sync is ahead of the RPC events tip - the newest queryable ledger is: {0:?}")]
    RpcAhead(u32),
    #[error("invalid latestLedger value: {0}")]
    InvalidLatestLedger(i64),
    #[error("missing required contract keys for {contract_id}: {missing_keys:?}")]
    MissingRequiredContractKeys {
        contract_id: String,
        missing_keys: Vec<String>,
    },
    #[error("RPC request timed out")]
    Timeout,
    #[error("too many contract IDs for a single event filter: {0} (max {MAX_FILTER_CONTRACT_IDS})")]
    TooManyContracts(usize),
}

// JSON-RPC Plumbing
#[derive(Serialize)]
struct JsonRpcRequest<T> {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: T,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcErrorResponse>,
}

#[derive(Deserialize)]
struct JsonRpcErrorResponse {
    code: i64,
    message: String,
    data: Option<serde_json::Value>,
}

const RETENTION_HANDOFF_CODE: i64 = -32_002;

/// The name a contract's instance entry is reported under.
///
/// [`Client::get_contract_data_bulk`] both labels the entry with this name and
/// recognizes it by the same name when it flattens the settings out of the
/// entry's storage map, so the two sides cannot drift apart.
const CONTRACT_INSTANCE_KEY: &str = "__contract_instance";

fn retention_handoff_from_data(data: Option<serde_json::Value>) -> Option<u32> {
    let value = data?;
    let ledger = value.get("fromLedger")?.as_u64()?;
    u32::try_from(ledger).ok()
}

fn map_json_rpc_error(err: JsonRpcErrorResponse) -> Error {
    if err.code == RETENTION_HANDOFF_CODE
        && let Some(from_ledger) = retention_handoff_from_data(err.data)
    {
        return Error::RetentionHandoff { from_ledger };
    }
    Error::JsonRpc {
        code: err.code,
        message: err.message,
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetLatestLedgerResponse {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
}

pub type SegmentFilter = String;
pub type TopicFilter = Vec<SegmentFilter>;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventType {
    All,
    Contract,
    System,
}

/// An inclusive ledger range. Construct via [`EventStart::ledger_range`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct LedgerRange {
    start: u32,
    end: u32,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum EventStart {
    Ledger(u32),
    /// A range of ledgers, inclusive. Use [`EventStart::ledger_range`] to
    /// construct this variant with validation.
    LedgerRange(LedgerRange),
    Cursor(String),
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetEventsResponse {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub events: Vec<Event>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
    #[serde(rename = "latestLedgerCloseTime")]
    pub latest_ledger_close_time: String,
    #[serde(rename = "oldestLedger")]
    pub oldest_ledger: u32,
    #[serde(rename = "oldestLedgerCloseTime")]
    pub oldest_ledger_close_time: String,
    pub cursor: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct Event {
    #[serde(rename = "type")]
    pub event_type: String,

    pub ledger: u32,
    #[serde(rename = "ledgerClosedAt")]
    pub ledger_closed_at: String,
    #[serde(rename = "contractId")]
    pub contract_id: String,

    pub id: String,

    #[serde(
        rename = "operationIndex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub operation_index: Option<u32>,
    #[serde(
        rename = "transactionIndex",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub transaction_index: Option<u32>,
    #[serde(rename = "txHash", default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[deprecated(
        note = "This field is deprecated by Stellar RPC. See https://stellar.org/blog/developers/protocol-23-upgrade-guide"
    )]
    #[serde(
        rename = "inSuccessfulContractCall",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_successful_contract_call: Option<bool>,

    pub topic: Vec<String>,
    pub value: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct LedgerEntryResult {
    pub key: String,
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger: u32,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GetLedgerEntriesResponse {
    pub entries: Option<Vec<LedgerEntryResult>>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: i64,
}

pub struct ContractDataBulkRequest<'a> {
    pub contract_id: &'a str,
    pub enum_keys: Vec<&'a str>,
}

#[derive(Default, Deserialize, Serialize, Debug, Clone)]
pub struct SimulateHostFunctionResult {
    #[serde(deserialize_with = "deserialize_default_from_null", default)]
    pub auth: Vec<String>,
    /// Legacy RPC field; may be absent on newer RPC servers.
    #[serde(default)]
    pub retval: Option<String>,
    /// Current RPC field for read-only simulation results.
    #[serde(default)]
    pub xdr: Option<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SimulateTransactionResponse {
    #[serde(rename = "latestLedger")]
    pub latest_ledger: i64,
    /// Some RPC clients normalize `results[0]` into `result`. Accept both.
    #[serde(default)]
    pub result: Option<SimulateHostFunctionResult>,
    #[serde(deserialize_with = "deserialize_default_from_null", default)]
    pub results: Vec<SimulateHostFunctionResult>,
    #[serde(rename = "transactionData", default)]
    pub transaction_data: Option<String>,
    #[serde(rename = "minResourceFee", default)]
    pub min_resource_fee: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Response from Soroban RPC `sendTransaction`.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SendTransactionResponse {
    pub hash: String,
    pub status: String,
    #[serde(rename = "errorResultXdr", default)]
    pub error_result_xdr: Option<String>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: u32,
}

/// Response from Soroban RPC `getTransaction`.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct GetTransactionResponse {
    pub status: String,
    #[serde(rename = "resultXdr", default)]
    pub result_xdr: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    http_client: reqwest::Client,
    #[cfg(target_arch = "wasm32")]
    timeout_secs: u32,
}

impl Client {
    const DEFAULT_TIMEOUT_SECS: u32 = 30;
    // https://developers.stellar.org/docs/data/apis/rpc/api-reference/methods/getLedgerEntries
    const MAX_LEDGER_KEYS_PER_REQUEST: usize = 200;

    /// Creates a client with the default 30-second timeout.
    pub fn new(base_url: &str) -> Result<Self, Error> {
        Self::with_timeout(base_url, Self::DEFAULT_TIMEOUT_SECS)
    }

    /// Creates a client with a custom timeout in seconds.
    pub fn with_timeout(base_url: &str, timeout_secs: u32) -> Result<Self, Error> {
        let uri = base_url.parse::<Uri>()?;
        let mut parts = uri.into_parts();

        if let (Some(scheme), Some(authority)) = (&parts.scheme, &parts.authority)
            && authority.port().is_none()
        {
            let port = match scheme.as_str() {
                "http" => Some(80),
                "https" => Some(443),
                _ => None,
            };
            if let Some(port) = port {
                let host = authority.host();
                parts.authority = Some(Authority::from_str(&format!("{host}:{port}"))?);
            }
        }

        let uri = Uri::from_parts(parts)?;
        let base_url = uri.to_string();

        #[cfg(not(target_arch = "wasm32"))]
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(u64::from(timeout_secs)))
            .build()?;
        #[cfg(target_arch = "wasm32")]
        let http_client = reqwest::Client::builder().build()?;

        Ok(Self {
            base_url,
            http_client,
            #[cfg(target_arch = "wasm32")]
            timeout_secs,
        })
    }

    async fn rpc_call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, Error> {
        tracing::debug!(method = method, "rpc_call_event");

        let payload = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method,
            params,
        };

        let request = async {
            self.http_client
                .post(&self.base_url)
                .json(&payload)
                .send()
                .await?
                .json::<JsonRpcResponse<R>>()
                .await
        };

        #[cfg(target_arch = "wasm32")]
        let resp = race_with_timeout(request, self.timeout_secs).await?;

        #[cfg(not(target_arch = "wasm32"))]
        let resp = request.await?;

        if let Some(err) = resp.error {
            return Err(map_json_rpc_error(err));
        }

        resp.result
            .ok_or_else(|| Error::NotFound("RPC Result", method.to_string()))
    }

    pub async fn get_contract_events(
        &self,
        contract_ids: &[String],
        start_ledger: u32,
        page_size: usize,
        cursor: Option<String>,
    ) -> Result<(Option<String>, Vec<Event>, u32), Error> {
        let start = cursor
            .as_ref()
            .map(|c| EventStart::Cursor(c.clone()))
            .unwrap_or(EventStart::Ledger(start_ledger));

        let mut resp = match self
            .get_events(
                start,
                Some(EventType::Contract),
                contract_ids,
                &[vec!["**".to_string()]],
                Some(page_size),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                if matches!(e, Error::RetentionHandoff { .. }) {
                    return Err(e);
                }
                if let Error::JsonRpc { message, .. } = &e
                    && let Some((oldest, newest)) = parse_ledger_range(message)
                {
                    // Requested a ledger older than the RPC retains: a real
                    // gap.
                    if start_ledger < oldest {
                        return Err(Error::RpcSyncGap(oldest));
                    }
                    // Requested a ledger past the RPC's queryable events tip:
                    // we are already caught up and the RPC
                    // simply hasn't indexed this far yet
                    // (its events tip lags the chain tip). Not an
                    // error — callers treat this as "nothing new this round".
                    if start_ledger > newest {
                        return Err(Error::RpcAhead(newest));
                    }
                }
                // Surface what we actually requested so range errors are
                // diagnosable.
                if let Error::JsonRpc { code, message } = e {
                    return Err(Error::JsonRpc {
                        code,
                        message: format!(
                            "{message} (requested startLedger={start_ledger}, cursor={})",
                            cursor.as_deref().unwrap_or("<none>")
                        ),
                    });
                }
                return Err(e);
            }
        };

        Ok((
            Some(resp.cursor),
            std::mem::take(&mut resp.events),
            resp.latest_ledger,
        ))
    }

    pub async fn get_events(
        &self,
        start: EventStart,
        event_type: Option<EventType>,
        contract_ids: &[String],
        topics: &[TopicFilter],
        limit: Option<usize>,
    ) -> Result<GetEventsResponse, Error> {
        if contract_ids.len() > MAX_FILTER_CONTRACT_IDS {
            return Err(Error::TooManyContracts(contract_ids.len()));
        }

        let type_str = event_type.and_then(|t| match t {
            EventType::All => None,
            EventType::Contract => Some("contract"),
            EventType::System => Some("system"),
        });

        // The RPC caps each filter at MAX_CONTRACT_IDS_PER_FILTER contract
        // IDs, but a request may carry up to MAX_FILTERS_PER_REQUEST
        // filters, whose results are merged into one cursor-ordered stream.
        let filters: Vec<serde_json::Map<String, serde_json::Value>> = contract_ids
            .chunks(MAX_CONTRACT_IDS_PER_FILTER)
            .map(|chunk| {
                let mut f = serde_json::Map::new();
                if let Some(t) = type_str {
                    f.insert("type".to_string(), t.into());
                }
                f.insert("topics".to_string(), topics.into());
                f.insert("contractIds".to_string(), chunk.into());
                f
            })
            .collect();

        let mut pagination = serde_json::Map::new();
        if let Some(limit) = limit {
            pagination.insert("limit".to_string(), limit.into());
        }

        let mut params = json!({
            "filters": filters,
            "pagination": pagination,
        });

        match start {
            EventStart::Ledger(l) => {
                params["startLedger"] = json!(l);
            }
            EventStart::LedgerRange(r) => {
                params["startLedger"] = json!(r.start);
                params["endLedger"] = json!(r.end);
            }
            EventStart::Cursor(c) => {
                params["pagination"]["cursor"] = json!(c);
            }
        }

        self.rpc_call("getEvents", params).await
    }

    pub async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse, Error> {
        self.rpc_call("getLatestLedger", json!({})).await
    }

    pub async fn get_ledger_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<GetLedgerEntriesResponse, Error> {
        let base64_keys: Vec<String> = keys
            .iter()
            .map(|k| k.to_xdr_base64(Limits::none()))
            .collect::<Result<Vec<_>, _>>()?;

        let params = json!({ "keys": base64_keys });
        self.rpc_call("getLedgerEntries", params).await
    }

    fn build_contract_data_key_specs<'a>(
        &self,
        contract_id: &str,
        enum_keys: &[&'a str],
    ) -> Result<Vec<(LedgerKey, &'a str)>, Error> {
        let contract =
            stellar_strkey::Contract::from_str(contract_id).map_err(Error::InvalidAddress)?;

        let contract_address = xdr::ScAddress::Contract(ContractId(xdr::Hash(contract.0)));

        let mut out = Vec::with_capacity(1usize.saturating_add(enum_keys.len()));

        out.push((
            LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract_address.clone(),
                key: xdr::ScVal::LedgerKeyContractInstance,
                durability: xdr::ContractDataDurability::Persistent,
            }),
            CONTRACT_INSTANCE_KEY,
        ));

        for variant in enum_keys.iter().copied() {
            let symbol =
                xdr::ScSymbol::try_from(variant).map_err(|_| Error::Xdr(XdrError::Invalid))?;
            let sc_vec = xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(symbol)])?;

            out.push((
                LedgerKey::ContractData(xdr::LedgerKeyContractData {
                    contract: contract_address.clone(),
                    key: xdr::ScVal::Vec(Some(sc_vec)),
                    durability: xdr::ContractDataDurability::Persistent,
                }),
                variant,
            ));
        }

        Ok(out)
    }

    pub async fn get_contract_data_bulk(
        &self,
        requests: &[ContractDataBulkRequest<'_>],
    ) -> Result<(HashMap<String, HashMap<String, xdr::ScVal>>, u32), Error> {
        #[derive(Clone)]
        struct KeyMeta {
            contract_id: String,
            key_name: String,
            required: bool,
        }

        let mut all_keys: Vec<LedgerKey> = Vec::new();
        let mut key_meta_by_xdr: HashMap<String, KeyMeta> = HashMap::new();

        for request in requests {
            let specs = self
                .build_contract_data_key_specs(request.contract_id, request.enum_keys.as_slice())?;

            for (key, key_name) in specs {
                let key_xdr = key.to_xdr_base64(Limits::none())?;
                key_meta_by_xdr.entry(key_xdr).or_insert_with(|| {
                    all_keys.push(key);
                    KeyMeta {
                        contract_id: request.contract_id.to_string(),
                        key_name: key_name.to_string(),
                        required: key_name != CONTRACT_INSTANCE_KEY,
                    }
                });
            }
        }

        if all_keys.is_empty() {
            return Ok((HashMap::new(), 0));
        }

        let mut expected_required: HashMap<String, BTreeSet<String>> = HashMap::new();
        for meta in key_meta_by_xdr.values() {
            if meta.required {
                expected_required
                    .entry(meta.contract_id.clone())
                    .or_default()
                    .insert(meta.key_name.clone());
            }
        }

        let mut latest_ledger = u32::MAX;
        let mut result: HashMap<String, HashMap<String, xdr::ScVal>> = HashMap::new();
        let mut actual_required: HashMap<String, BTreeSet<String>> = HashMap::new();

        for chunk in all_keys.chunks(Self::MAX_LEDGER_KEYS_PER_REQUEST) {
            let response = self.get_ledger_entries(chunk).await?;
            let chunk_latest_ledger: u32 = response
                .latest_ledger
                .try_into()
                .map_err(|_| Error::InvalidLatestLedger(response.latest_ledger))?;
            latest_ledger = latest_ledger.min(chunk_latest_ledger);

            for entry in response.entries.unwrap_or_default() {
                let Some(meta) = key_meta_by_xdr.get(&entry.key) else {
                    continue;
                };

                let LedgerEntryData::ContractData(data) =
                    LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())?
                else {
                    continue;
                };

                let contract_state = result.entry(meta.contract_id.clone()).or_default();
                // The instance entry carries the contract's settings in its
                // storage map, so they land in the same map as the entries
                // fetched under their own ledger keys.
                if meta.key_name == CONTRACT_INSTANCE_KEY
                    && let xdr::ScVal::ContractInstance(instance) = &data.val
                {
                    contract_state.extend(instance_storage_entries(instance));
                }
                contract_state.insert(meta.key_name.clone(), data.val);

                if meta.required {
                    actual_required
                        .entry(meta.contract_id.clone())
                        .or_default()
                        .insert(meta.key_name.clone());
                }
            }
        }

        for (contract_id, expected) in expected_required {
            let actual = actual_required
                .get(&contract_id)
                .cloned()
                .unwrap_or_default();
            let missing: Vec<String> = expected.difference(&actual).cloned().collect();

            if !missing.is_empty() {
                return Err(Error::MissingRequiredContractKeys {
                    contract_id,
                    missing_keys: missing,
                });
            }
        }

        Ok((result, latest_ledger))
    }

    #[tracing::instrument(name = "simulate_transaction", level = "info", skip_all, fields(correlation_id = %crate::types::correlation_id_or_new()))]
    pub async fn simulate_transaction(
        &self,
        tx: &xdr::TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, Error> {
        let transaction = tx.to_xdr_base64(Limits::none())?;
        let params = json!({ "transaction": transaction });
        self.rpc_call("simulateTransaction", params).await
    }

    pub async fn get_account(&self, address: &str) -> Result<AccountEntry, Error> {
        let pk = stellar_strkey::ed25519::PublicKey::from_str(address)?;
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk.0))),
        });
        let response = self.get_ledger_entries(&[key]).await?;
        let entries = response.entries.unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::NotFound("Account", address.to_string()));
        }
        match LedgerEntryData::from_xdr_base64(&entries[0].xdr, Limits::none())? {
            LedgerEntryData::Account(entry) => Ok(entry),
            _ => Err(Error::UnexpectedScVal(
                "expected account ledger entry".into(),
            )),
        }
    }

    /// Trustline balance of `address` in the classic asset `code:issuer`, in
    /// its smallest unit. Returns 0 if there is no such trustline.
    pub async fn get_trustline_balance(
        &self,
        address: &str,
        code: &str,
        issuer: &str,
    ) -> Result<u128, Error> {
        let account_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            stellar_strkey::ed25519::PublicKey::from_str(address)?.0,
        )));
        let issuer_id = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            stellar_strkey::ed25519::PublicKey::from_str(issuer)?.0,
        )));
        let asset = match code.parse::<xdr::AssetCode4>() {
            Ok(asset_code) => xdr::TrustLineAsset::CreditAlphanum4(xdr::AlphaNum4 {
                asset_code,
                issuer: issuer_id,
            }),
            Err(_) => xdr::TrustLineAsset::CreditAlphanum12(xdr::AlphaNum12 {
                asset_code: code
                    .parse()
                    .map_err(|_| Error::UnexpectedScVal(format!("invalid asset code: {code}")))?,
                issuer: issuer_id,
            }),
        };
        let key = LedgerKey::Trustline(xdr::LedgerKeyTrustLine { account_id, asset });
        let response = self.get_ledger_entries(&[key]).await?;
        let entries = response.entries.unwrap_or_default();
        let Some(entry) = entries.first() else {
            return Ok(0);
        };
        match LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())? {
            LedgerEntryData::Trustline(entry) => u128::try_from(entry.balance).map_err(|_| {
                Error::UnexpectedScVal(format!("negative trustline balance: {}", entry.balance))
            }),
            _ => Err(Error::UnexpectedScVal(
                "expected trustline ledger entry".into(),
            )),
        }
    }

    /// Balance of `address` reported by the SEP-41 token contract
    /// `contract_id`. Returns 0 if `address` has no balance.
    pub async fn get_token_balance(&self, contract_id: &str, address: &str) -> Result<u128, Error> {
        let arg = address
            .parse()
            .map_err(|_| Error::UnexpectedScVal(format!("invalid address: {address}")))?;
        let tx = build_invoke_contract_tx_envelope(
            address,
            xdr::SequenceNumber(0),
            BASE_FEE,
            contract_id,
            "balance",
            vec![xdr::ScVal::Address(arg)],
            Vec::new(),
        )
        .map_err(|e| Error::UnexpectedScVal(e.to_string()))?;

        let sim = self.simulate_transaction(&tx).await?;
        let op_result = sim
            .result
            .or_else(|| sim.results.into_iter().next())
            .ok_or_else(|| {
                Error::UnexpectedScVal("simulateTransaction returned no results".into())
            })?;
        let retval_b64 = op_result
            .retval
            .or(op_result.xdr)
            .ok_or_else(|| Error::UnexpectedScVal("simulateTransaction missing retval".into()))?;
        match xdr::ScVal::from_xdr_base64(&retval_b64, Limits::none())? {
            xdr::ScVal::I128(parts) => {
                let value = i128::from(&parts);
                u128::try_from(value).map_err(|_| {
                    Error::UnexpectedScVal(format!(
                        "token contract reported a negative balance: {value}"
                    ))
                })
            }
            other => Err(Error::UnexpectedScVal(format!(
                "expected balance() to return i128, got {other:?}"
            ))),
        }
    }

    /// Submits a signed transaction envelope to the network.
    #[tracing::instrument(name = "send_transaction", level = "info", skip_all, fields(correlation_id = %crate::types::correlation_id_or_new()))]
    pub async fn send_transaction(
        &self,
        tx: &xdr::TransactionEnvelope,
    ) -> Result<SendTransactionResponse, Error> {
        let transaction = tx.to_xdr_base64(Limits::none())?;
        let params = json!({ "transaction": transaction });
        let resp: SendTransactionResponse = self.rpc_call("sendTransaction", params).await?;
        if resp.status == "ERROR" {
            tracing::warn!(hash = %resp.hash, status = %resp.status, "send_transaction_failed");
            return Err(Error::JsonRpc {
                code: -1,
                message: format!(
                    "sendTransaction failed: {}",
                    resp.error_result_xdr.unwrap_or_default()
                ),
            });
        }
        Ok(resp)
    }

    /// Fetches transaction status by hash.
    #[tracing::instrument(name = "get_transaction", level = "info", skip_all, fields(correlation_id = %crate::types::correlation_id_or_new(), hash = %hash))]
    pub async fn get_transaction(&self, hash: &str) -> Result<GetTransactionResponse, Error> {
        let params = json!({ "hash": hash });
        self.rpc_call("getTransaction", params).await
    }
}

/// Races a request future against a [`gloo_timers::future::TimeoutFuture`].
/// Returns [`Error::Timeout`] if the timer fires first.
#[cfg(target_arch = "wasm32")]
async fn race_with_timeout<F, T>(fut: F, timeout_secs: u32) -> Result<T, Error>
where
    F: std::future::Future<Output = Result<T, reqwest::Error>>,
{
    use futures::future::Either;
    use gloo_timers::future::TimeoutFuture;

    let timeout_ms = timeout_secs.saturating_mul(1_000);
    futures::pin_mut!(fut);
    match futures::future::select(fut, TimeoutFuture::new(timeout_ms)).await {
        Either::Left((result, _)) => result.map_err(Error::from),
        Either::Right(..) => Err(Error::Timeout),
    }
}

// helper to parse "startLedger must be within the ledger range: 1936296 -
// 2057255" from the RPC message
fn parse_ledger_range(message: &str) -> Option<(u32, u32)> {
    let parts: Vec<&str> = message.split(":").collect();
    if parts.len() != 2 {
        return None;
    }
    let range = parts[1].trim();
    if let Some((start, end)) = range.split_once('-') {
        let start = start.trim().parse().ok()?;
        let end = end.trim().parse().ok()?;
        return Some((start, end));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONTRACT_ID: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

    fn test_client() -> Client {
        Client::new("https://example.org").expect("client")
    }

    #[test]
    fn parse_retention_handoff_error() {
        let err = map_json_rpc_error(JsonRpcErrorResponse {
            code: RETENTION_HANDOFF_CODE,
            message: "Continue syncing on your RPC endpoint".into(),
            data: Some(json!({ "fromLedger": 2_913_600 })),
        });
        assert!(matches!(
            err,
            Error::RetentionHandoff {
                from_ledger: 2_913_600
            }
        ));
    }

    /// The instance entry is fetched for every contract, under the one name
    /// [`Client::get_contract_data_bulk`] never requires: the settings it
    /// carries are reported as missing under their own names, by the caller
    /// that reads them.
    #[test]
    fn the_instance_entry_is_fetched_with_the_named_keys() {
        let specs = test_client()
            .build_contract_data_key_specs(TEST_CONTRACT_ID, &["Admin", "State"])
            .expect("key specs");

        let names: Vec<&str> = specs.iter().map(|(_, name)| *name).collect();

        assert_eq!(names, vec![CONTRACT_INSTANCE_KEY, "Admin", "State"]);
    }

    #[test]
    fn parsing_range_error() {
        let msg = "startLedger must be within the ledger range: 1936296 - 2057255";
        assert_eq!(Some((1936296, 2057255)), parse_ledger_range(msg));
    }

    /// A persistent entry of the test contract under `key`, with the ledger key
    /// that addresses it.
    #[cfg(not(target_arch = "wasm32"))]
    fn contract_data_entry(key: xdr::ScVal, val: xdr::ScVal) -> (LedgerKey, LedgerEntryData) {
        let contract = stellar_strkey::Contract::from_str(TEST_CONTRACT_ID).expect("contract id");
        let contract = xdr::ScAddress::Contract(ContractId(xdr::Hash(contract.0)));
        let durability = xdr::ContractDataDurability::Persistent;
        (
            LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract.clone(),
                key: key.clone(),
                durability,
            }),
            LedgerEntryData::ContractData(xdr::ContractDataEntry {
                ext: xdr::ExtensionPoint::V0,
                contract,
                key,
                durability,
                val,
            }),
        )
    }

    /// The ledger key of a unit `DataKey` variant, a one-symbol vector.
    #[cfg(not(target_arch = "wasm32"))]
    fn symbol_key(name: &str) -> xdr::ScVal {
        xdr::ScVal::Vec(Some(
            xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(
                xdr::ScSymbol::try_from(name).expect("symbol"),
            )])
            .expect("key vector"),
        ))
    }

    /// A mock RPC that answers every request with `entries`.
    #[cfg(not(target_arch = "wasm32"))]
    async fn rpc_serving(entries: &[(LedgerKey, LedgerEntryData)]) -> wiremock::MockServer {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

        let entries: Vec<_> = entries
            .iter()
            .map(|(key, entry)| {
                json!({
                    "key": key.to_xdr_base64(Limits::none()).expect("key xdr"),
                    "xdr": entry.to_xdr_base64(Limits::none()).expect("entry xdr"),
                    "lastModifiedLedgerSeq": 4_656_000,
                    "liveUntilLedgerSeq": 4_700_000,
                })
            })
            .collect();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": { "latestLedger": 4_656_112, "entries": entries },
            })))
            .mount(&server)
            .await;
        server
    }

    /// The instance entry is the one key the bulk read never requires, so a
    /// contract whose instance entry is absent from the response still reads.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn a_missing_instance_entry_is_not_required() {
        let server =
            rpc_serving(&[contract_data_entry(symbol_key("Admin"), xdr::ScVal::U32(7))]).await;

        let (state, _) = Client::new(&server.uri())
            .expect("client")
            .get_contract_data_bulk(&[ContractDataBulkRequest {
                contract_id: TEST_CONTRACT_ID,
                enum_keys: vec!["Admin"],
            }])
            .await
            .expect("a missing instance entry is not an error");

        let contract_state = state.get(TEST_CONTRACT_ID).expect("contract state");
        assert_eq!(contract_state.get("Admin"), Some(&xdr::ScVal::U32(7)));
        assert!(!contract_state.contains_key(CONTRACT_INSTANCE_KEY));
    }

    /// The settings a contract keeps in its instance entry have to reach the
    /// caller under their own names, which only the flattening branch of
    /// [`Client::get_contract_data_bulk`] does. Nothing else fetches them, so
    /// without this the branch could be dropped and every other test in the
    /// workspace would still pass.
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn instance_storage_settings_arrive_under_their_own_names() {
        let instance = xdr::ScVal::ContractInstance(xdr::ScContractInstance {
            executable: xdr::ContractExecutable::Wasm(xdr::Hash([7u8; 32])),
            storage: Some(
                xdr::ScMap::try_from(vec![xdr::ScMapEntry {
                    key: symbol_key("Levels"),
                    val: xdr::ScVal::U32(20),
                }])
                .expect("storage map"),
            ),
        });
        let server = rpc_serving(&[contract_data_entry(
            xdr::ScVal::LedgerKeyContractInstance,
            instance,
        )])
        .await;

        let (state, _) = Client::new(&server.uri())
            .expect("client")
            .get_contract_data_bulk(&[ContractDataBulkRequest {
                contract_id: TEST_CONTRACT_ID,
                enum_keys: vec![],
            }])
            .await
            .expect("bulk read");

        let contract_state = state.get(TEST_CONTRACT_ID).expect("contract state");
        assert_eq!(contract_state.get("Levels"), Some(&xdr::ScVal::U32(20)));
    }

    #[cfg(target_arch = "wasm32")]
    mod wasm {
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        #[wasm_bindgen_test]
        async fn timeout_fires_when_request_pending() {
            let pending: futures::future::Pending<Result<(), reqwest::Error>> =
                futures::future::pending();
            let result: Result<(), Error> = race_with_timeout(pending, 0).await;
            assert!(matches!(result, Err(Error::Timeout)));
        }

        #[wasm_bindgen_test]
        async fn returns_value_when_request_completes_first() {
            let ready: futures::future::Ready<Result<u32, reqwest::Error>> =
                futures::future::ready(Ok(42));
            let result: Result<u32, Error> = race_with_timeout(ready, 60).await;
            assert_eq!(result.expect("expected Ok"), 42);
        }
    }
}
