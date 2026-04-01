use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use std::collections::HashMap;
use http::{uri::Authority, Uri};
use serde_aux::prelude::{
    deserialize_default_from_null, deserialize_number_from_string,
    deserialize_option_number_from_string,
};
use stellar_strkey::ed25519;
use stellar_xdr::curr::{
    self as xdr, ContractDataEntry, Error as XdrError, LedgerEntryData,
    LedgerKey, Limits, ReadXdr, WriteXdr, ContractId
};
use num_bigint::BigUint;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    InvalidAddress(#[from] stellar_strkey::DecodeError),
    #[error("network error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("jsonrpc error: {code} - {message}")]
    JsonRpcError { code: i64, message: String },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(#[from] http::uri::InvalidUri),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrlFromUriParts(#[from] http::uri::InvalidUriParts),
    #[error("json decoding error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0} not found: {1}")]
    NotFound(String, String),
    #[error("unexpected contract code data type: {0:?}")]
    UnexpectedContractCodeDataType(LedgerEntryData),
    #[error("Duplicate key found in contract data: {0}")]
    DuplicateContractKey(String),
    #[error("Unexpected ScVal: {0:?}")]
    UnexpectedScVal(String),
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

#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    http_client: reqwest::Client,
}

impl Client {
    pub fn new(base_url: &str) -> Result<Self, Error> {
        let uri = base_url.parse::<Uri>()?;
        let mut parts = uri.into_parts();

        if let (Some(scheme), Some(authority)) = (&parts.scheme, &parts.authority) {
            if authority.port().is_none() {
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
        }

        let uri = Uri::from_parts(parts)?;
        let base_url = uri.to_string();

        let mut client_builder = reqwest::Client::builder();

        // TODO add timeout for WASM
        #[cfg(not(target_arch = "wasm32"))]
        {
            client_builder = client_builder.timeout(std::time::Duration::from_secs(30));
        }

        Ok(Self {
            base_url,
            http_client: client_builder.build()?,
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

        let resp: JsonRpcResponse<R> = self.http_client
            .post(&self.base_url)
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.error {
            return Err(Error::JsonRpcError { code: err.code, message: err.message });
        }

        // Replaced custom ok_ok with standard ok_or_else
        resp.result.ok_or_else(|| Error::NotFound("RPC Result".to_string(), method.to_string()))
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
                EventType::All => None, // all is the default, so avoid incl. the param
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

        Ok(self.rpc_call("getEvents", params).await?)
    }

    pub async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse, Error> {
            Ok(self
                .rpc_call("getLatestLedger", json!({}))
                .await?)
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

    pub async fn get_contract_data(
        &self,
        contract_id: &str,
        enum_keys: &[&str],
        valued_keys: &[(&str, u32)]
    ) -> Result<HashMap<String, xdr::ScVal>, Error> {
        let contract = stellar_strkey::Contract::from_str(contract_id)
                .map_err(|e| Error::InvalidAddress(e))?;

        let contract_address = xdr::ScAddress::Contract(ContractId(xdr::Hash(contract.0)));

        let contract_key = LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: contract_address.clone(),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability: xdr::ContractDataDurability::Persistent,
        });

        let mut keys = Vec::with_capacity(1 + enum_keys.len() + valued_keys.len());
        keys.push(contract_key);

        for variant in enum_keys {
            let symbol = xdr::ScSymbol::try_from(*variant).map_err(|_| Error::Xdr(XdrError::Invalid))?;
            let sc_vec = xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(symbol)])?;

            keys.push(LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract_address.clone(),
                key: xdr::ScVal::Vec(Some(sc_vec)),
                durability: xdr::ContractDataDurability::Persistent,
            }));
        }

        for (variant, value) in valued_keys {
            let symbol = xdr::ScSymbol::try_from(*variant).map_err(|_| Error::Xdr(XdrError::Invalid))?;
            let sc_vec = xdr::ScVec::try_from(vec![xdr::ScVal::Symbol(symbol), xdr::ScVal::U32(*value)])?;

            keys.push(LedgerKey::ContractData(xdr::LedgerKeyContractData {
                contract: contract_address.clone(),
                key: xdr::ScVal::Vec(Some(sc_vec)),
                durability: xdr::ContractDataDurability::Persistent,
            }));
        }

        let response = self.get_ledger_entries(&keys).await?;
        let entries = response.entries.unwrap_or_default();

        if entries.is_empty() {
            let addr_str = stellar_strkey::Contract(contract.0).to_string();
            return Err(Error::NotFound("Contract/Keys".to_string(), addr_str));
        }

        let mut results_map = HashMap::new();

        for entry in entries {
            match LedgerEntryData::from_xdr_base64(&entry.xdr, Limits::none())? {
                LedgerEntryData::ContractData(data) => {
                    // TODO - come up with more elegant parsing
                    let key_name: String = extract_symbol_from_val(&data.key).unwrap_or_else(|_| format!("{:?}", data.key));
                    if results_map.insert(key_name.clone(), data.val).is_some() {
                        return Err(Error::DuplicateContractKey(key_name));
                    }
                }
                _ => continue,
            }
        }
        Ok(results_map)
    }
}


fn extract_symbol_from_val(key: &xdr::ScVal) -> Result<String, Error> {
    if let xdr::ScVal::Vec(Some(sc_vec)) = key {
        let first_inner_val = sc_vec.0.get(0).ok_or_else(|| Error::UnexpectedScVal(format!("ScVal vec is empty {:?}", key)))?;

        if let xdr::ScVal::Symbol(symbol) = first_inner_val {

            return Ok(symbol.0.to_string());
        }
    }

    Err(Error::UnexpectedScVal("Structure {key:?} did not match ScVal::Vec(ScVal::Symbol)".to_string()))
}

/// Helper to convert ScVal Address to G... or C... string
pub fn scval_to_address_string(val: &xdr::ScVal) -> Result<String, Error> {
    if let xdr::ScVal::Address(addr) = val {
        match addr {
            xdr::ScAddress::Account(account_id) => {
                // AccountId -> PublicKey enum -> PublicKeyTypeEd25519 variant -> Uint256
                let xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(bytes)) = &account_id.0;
                Ok(ed25519::PublicKey(*bytes).to_string())
            }
            xdr::ScAddress::Contract(contract_id) => {
                let bytes = contract_id.0.0;
                Ok(stellar_strkey::Contract(bytes).to_string())
            }
            // Handling MuxedAccount, ClaimableBalance, and LiquidityPool
            _ => Err(Error::UnexpectedScVal(format!("Unsupported Address type: {addr:?}"))),
        }
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

/// Helper to convert U256Parts to BigUint
pub fn scval_to_u256(val: &xdr::ScVal) -> Result<BigUint, Error> {
    if let xdr::ScVal::U256(parts) = val {
        let hi_hi = BigUint::from(parts.hi_hi);
        let hi_lo = BigUint::from(parts.hi_lo);
        let lo_hi = BigUint::from(parts.lo_hi);
        let lo_lo = BigUint::from(parts.lo_lo);

        let total: BigUint = (hi_hi << 192) + (hi_lo << 128) + (lo_hi << 64) + lo_lo;

        Ok(total)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

pub fn scval_to_u32(val: &xdr::ScVal) -> Result<u32, Error> {
    if let xdr::ScVal::U32(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

pub fn scval_to_u64(val: &xdr::ScVal) -> Result<u64, Error> {
    if let xdr::ScVal::U64(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}


pub fn scval_to_bool(val: &xdr::ScVal) -> Result<bool, Error> {
    if let xdr::ScVal::Bool(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}
