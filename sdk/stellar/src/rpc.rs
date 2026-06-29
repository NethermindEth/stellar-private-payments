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
    pub valued_keys: Vec<(&'a str, u32)>,
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
                    && let Some((oldest, newest)) = parse_ledger_range(message)
                {
                    // Requested a ledger older than the RPC retains: a real gap.
                    if start_ledger < oldest {
                        return Err(Error::RpcSyncGap(oldest));
                    }
                    // Requested a ledger past the RPC's queryable events tip: we
                    // are already caught up and the RPC simply hasn't indexed
                    // this far yet (its events tip lags the chain tip). Not an
                    // error — callers treat this as "nothing new this round".
                    if start_ledger > newest {
                        return Err(Error::RpcAhead(newest));
                    }
                }
                // Surface what we actually requested so range errors are diagnosable.
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

    #[test]
    fn parsing_range_error() {
        let msg = "startLedger must be within the ledger range: 1936296 - 2057255";
        assert_eq!(Some((1936296, 2057255)), parse_ledger_range(msg));
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
