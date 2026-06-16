// many parts are taken from https://github.com/stellar/rs-stellar-rpc-client/blob/main/src/lib.rs
// to make it wasm-compatible

use http::{Uri, uri::Authority};
use serde::{Deserialize, Serialize};
use serde_aux::prelude::deserialize_default_from_null;
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    str::FromStr,
};
use stellar_xdr::curr::{
    self as xdr, AccountEntry, AccountId, ContractId, Error as XdrError, LedgerEntryData,
    LedgerKey, LedgerKeyAccount, Limits, PublicKey, ReadXdr, Uint256, WriteXdr,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    InvalidAddress(#[from] stellar_strkey::DecodeError),
    #[error("network error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("jsonrpc error: {code} - {message}")]
    JsonRpc { code: i64, message: String },
    #[error("bootnode handoff at ledger {from_ledger}")]
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
    #[error("invalid latestLedger value: {0}")]
    InvalidLatestLedger(i64),
    #[error("missing required contract keys for {contract_id}: {missing_keys:?}")]
    MissingRequiredContractKeys {
        contract_id: String,
        missing_keys: Vec<String>,
    },
    #[error("RPC request timed out")]
    Timeout,
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
    #[serde(default)]
    data: Option<serde_json::Value>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetEventsParams {
    #[serde(default)]
    pub filters: Vec<ContractEventFilter>,
    #[serde(default)]
    pub pagination: PaginationParams,
    #[serde(rename = "startLedger", default)]
    pub start_ledger: Option<u32>,
    #[serde(rename = "endLedger", default)]
    pub end_ledger: Option<u32>,
    #[serde(rename = "xdrFormat", default)]
    pub xdr_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractEventFilter {
    #[serde(rename = "type")]
    pub filter_type: String,
    pub topics: Vec<TopicFilter>,
    #[serde(rename = "contractIds")]
    pub contract_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationParams {
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGetEvents {
    pub start_ledger: Option<u32>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

impl GetEventsParams {
    pub fn parsed(&self) -> anyhow::Result<ParsedGetEvents> {
        match (self.start_ledger, self.pagination.cursor.as_deref()) {
            (Some(_), Some(_)) => anyhow::bail!(
                "getEvents params must include either startLedger or pagination.cursor, not both"
            ),
            (None, None) => anyhow::bail!(
                "getEvents params must include either startLedger or pagination.cursor"
            ),
            _ => Ok(ParsedGetEvents {
                start_ledger: self.start_ledger,
                cursor: self.pagination.cursor.clone(),
                limit: self.pagination.limit,
            }),
        }
    }

    pub fn is_allowed_filters(&self, allowed_contract_ids: &[String]) -> bool {
        let Some(first) = self.filters.first() else {
            return false;
        };

        if first.filter_type != "contract" {
            return false;
        }

        if first.topics != [vec!["**".to_string()]] {
            return false;
        }

        let mut got: Vec<&str> = first.contract_ids.iter().map(String::as_str).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = allowed_contract_ids.iter().map(String::as_str).collect();
        want.sort_unstable();
        got == want
    }

    pub fn for_contracts(
        contract_ids: &[String],
        start_ledger: Option<u32>,
        cursor: Option<&str>,
        limit: u32,
    ) -> Self {
        Self {
            filters: vec![ContractEventFilter {
                filter_type: "contract".to_string(),
                topics: vec![vec!["**".to_string()]],
                contract_ids: contract_ids.to_vec(),
            }],
            pagination: PaginationParams {
                limit: Some(limit),
                cursor: cursor.map(str::to_owned),
            },
            start_ledger,
            end_ledger: None,
            xdr_format: None,
        }
    }
}

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
    pub valued_keys: Vec<(&'a str, u32)>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SimulateHostFunctionResult {
    #[serde(deserialize_with = "deserialize_default_from_null", default)]
    pub auth: Vec<String>,
    #[serde(default)]
    pub retval: Option<String>,
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
            if err.code == -32005 {
                let from_ledger = err
                    .data
                    .as_ref()
                    .and_then(|d| d.get("fromLedger"))
                    .and_then(|v| v.as_u64())
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(|| Error::JsonRpc {
                        code: err.code,
                        message: "handoff missing fromLedger".into(),
                    })?;
                return Err(Error::RetentionHandoff { from_ledger });
            }
            return Err(Error::JsonRpc {
                code: err.code,
                message: err.message,
            });
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
                if let Error::JsonRpc { message, .. } = &e
                    && let Some(range) = parse_ledger_range(message).filter(|r| start_ledger < r.0)
                {
                    return Err(Error::RpcSyncGap(range.0));
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
        let mut filters = serde_json::Map::new();

        event_type
            .and_then(|t| match t {
                EventType::All => None,
                EventType::Contract => Some("contract"),
                EventType::System => Some("system"),
            })
            .map(|t| filters.insert("type".to_string(), t.into()));

        filters.insert("topics".to_string(), topics.into());
        filters.insert("contractIds".to_string(), contract_ids.into());

        let mut pagination = serde_json::Map::new();
        if let Some(limit) = limit {
            pagination.insert("limit".to_string(), limit.into());
        }

        let mut params = json!({
            "filters": [filters],
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
        valued_keys: &[(&'a str, u32)],
    ) -> Result<Vec<(LedgerKey, &'a str, bool)>, Error> {
        let contract =
            stellar_strkey::Contract::from_str(contract_id).map_err(Error::InvalidAddress)?;

        let contract_address = xdr::ScAddress::Contract(ContractId(xdr::Hash(contract.0)));

        let mut out = Vec::with_capacity(
            1usize
                .saturating_add(enum_keys.len())
                .saturating_add(valued_keys.len()),
        );

        out.push((
            LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract_address.clone(),
                key: xdr::ScVal::LedgerKeyContractInstance,
                durability: xdr::ContractDataDurability::Persistent,
            }),
            "__contract_instance",
            false,
        ));

        for variant in enum_keys {
            let symbol =
                xdr::ScSymbol::try_from(*variant).map_err(|_| Error::Xdr(XdrError::Invalid))?;
            let sc_vec = xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(symbol)])?;

            out.push((
                LedgerKey::ContractData(xdr::LedgerKeyContractData {
                    contract: contract_address.clone(),
                    key: xdr::ScVal::Vec(Some(sc_vec)),
                    durability: xdr::ContractDataDurability::Persistent,
                }),
                *variant,
                true,
            ));
        }

        for (variant, value) in valued_keys {
            let symbol =
                xdr::ScSymbol::try_from(*variant).map_err(|_| Error::Xdr(XdrError::Invalid))?;
            let sc_vec =
                xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(symbol), xdr::ScVal::U32(*value)])?;

            out.push((
                LedgerKey::ContractData(xdr::LedgerKeyContractData {
                    contract: contract_address.clone(),
                    key: xdr::ScVal::Vec(Some(sc_vec)),
                    durability: xdr::ContractDataDurability::Persistent,
                }),
                *variant,
                true,
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
            let specs = self.build_contract_data_key_specs(
                request.contract_id,
                request.enum_keys.as_slice(),
                request.valued_keys.as_slice(),
            )?;

            for (key, key_name, required) in specs {
                let key_xdr = key.to_xdr_base64(Limits::none())?;
                key_meta_by_xdr.entry(key_xdr).or_insert_with(|| {
                    all_keys.push(key);
                    KeyMeta {
                        contract_id: request.contract_id.to_string(),
                        key_name: key_name.to_string(),
                        required,
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

                result
                    .entry(meta.contract_id.clone())
                    .or_default()
                    .insert(meta.key_name.clone(), data.val);

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

    /// Submits a signed transaction envelope to the network.
    ///
    /// TODO(#162): Wire into the web UI via WASM so JS does not depend on
    /// `@stellar/stellar-sdk` for `sendTransaction` / `getTransaction`.
    #[allow(dead_code)]
    pub async fn send_transaction(
        &self,
        tx: &xdr::TransactionEnvelope,
    ) -> Result<SendTransactionResponse, Error> {
        let transaction = tx.to_xdr_base64(Limits::none())?;
        let params = json!({ "transaction": transaction });
        let resp: SendTransactionResponse = self.rpc_call("sendTransaction", params).await?;
        if resp.status == "ERROR" {
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
    ///
    /// TODO(#162): See [`Self::send_transaction`].
    #[allow(dead_code)]
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
    use serde_json::json;

    #[test]
    fn parsing_range_error() {
        let msg = "startLedger must be within the ledger range: 1936296 - 2057255";
        assert_eq!(Some((1936296, 2057255)), parse_ledger_range(msg));
    }

    #[test]
    fn for_contracts_shape() {
        let ids = vec!["CABC".to_string(), "CDEF".to_string()];
        let params = GetEventsParams::for_contracts(&ids, Some(100), Some("cursor-1"), 300);

        assert_eq!(params.start_ledger, Some(100));
        assert_eq!(params.pagination.limit, Some(300));
        assert_eq!(params.pagination.cursor.as_deref(), Some("cursor-1"));
        assert_eq!(params.filters[0].filter_type, "contract");
        assert_eq!(params.filters[0].topics, vec![vec!["**".to_string()]]);
        assert_eq!(params.filters[0].contract_ids, ids);
    }

    #[test]
    fn for_contracts_serializes_to_stellar_shape() {
        let params = GetEventsParams::for_contracts(&["CA".to_string()], Some(1), None, 10);
        let value = serde_json::to_value(params).expect("params should serialize");
        let roundtrip: GetEventsParams =
            serde_json::from_value(value).expect("params should deserialize");
        assert_eq!(roundtrip.start_ledger, Some(1));
    }

    #[test]
    fn parsed_start_ledger() {
        let params: GetEventsParams =
            serde_json::from_value(json!({"startLedger": 42, "pagination": {"limit": 100}}))
                .expect("params should deserialize");
        let parsed = params.parsed().expect("startLedger params should parse");
        assert_eq!(parsed.start_ledger, Some(42));
        assert!(parsed.cursor.is_none());
        assert_eq!(parsed.limit, Some(100));
    }

    #[test]
    fn parsed_cursor() {
        let params: GetEventsParams =
            serde_json::from_value(json!({"pagination": {"cursor": "abc", "limit": 50}}))
                .expect("params should deserialize");
        let parsed = params.parsed().expect("cursor params should parse");
        assert!(parsed.start_ledger.is_none());
        assert_eq!(parsed.cursor.as_deref(), Some("abc"));
        assert_eq!(parsed.limit, Some(50));
    }

    #[test]
    fn parsed_rejects_ambiguous_params() {
        let both: GetEventsParams =
            serde_json::from_value(json!({"startLedger": 1, "pagination": {"cursor": "x"}}))
                .expect("params should deserialize");
        assert!(both.parsed().is_err());

        let neither: GetEventsParams = serde_json::from_value(json!({"pagination": {"limit": 10}}))
            .expect("params should deserialize");
        assert!(neither.parsed().is_err());
    }

    fn sample_filters(ids: &[&str]) -> GetEventsParams {
        serde_json::from_value(json!({
            "filters": [{
                "type": "contract",
                "topics": [["**"]],
                "contractIds": ids
            }]
        }))
        .expect("filters should deserialize")
    }

    #[test]
    fn is_allowed_filters_match_exact_contract_set() {
        let allowed = vec!["CB".to_string(), "CA".to_string()];
        let params = sample_filters(&["CA", "CB"]);
        assert!(params.is_allowed_filters(&allowed));
    }

    #[test]
    fn is_allowed_filters_reject_wrong_contract_ids_or_topics() {
        let allowed = vec!["CA".to_string()];
        assert!(!sample_filters(&["CA", "CB"]).is_allowed_filters(&allowed));
        let params: GetEventsParams = serde_json::from_value(json!({
            "filters": [{"type": "contract", "topics": [["deposit"]], "contractIds": ["CA"]}]
        }))
        .expect("params should deserialize");
        assert!(!params.is_allowed_filters(&allowed));
    }

    #[test]
    fn get_events_response_parses_upstream_shape() {
        let result = json!({
            "cursor": "next",
            "events": [{
                "type": "contract",
                "ledger": 10,
                "ledgerClosedAt": "2024-01-01T00:00:00Z",
                "contractId": "CABC",
                "id": "1",
                "topic": ["deposit"],
                "value": "00"
            }],
            "latestLedger": 99,
            "latestLedgerCloseTime": "2024-01-01T00:00:00Z",
            "oldestLedger": 1,
            "oldestLedgerCloseTime": "2024-01-01T00:00:00Z"
        });
        let parsed: GetEventsResponse =
            serde_json::from_value(result).expect("valid getEvents result should parse");
        assert_eq!(parsed.cursor, "next");
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.latest_ledger, 99);
        assert_eq!(parsed.oldest_ledger, 1);
    }

    #[test]
    fn get_events_response_requires_fields() {
        assert!(serde_json::from_value::<GetEventsResponse>(json!({})).is_err());
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
