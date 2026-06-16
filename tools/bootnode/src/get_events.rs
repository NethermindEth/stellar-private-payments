use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GetEventsParams {
    #[serde(default)]
    pub filters: Vec<ContractEventFilter>,
    #[serde(default)]
    pub pagination: PaginationParams,
    #[serde(rename = "startLedger", default)]
    pub start_ledger: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ContractEventFilter {
    #[serde(rename = "type")]
    pub filter_type: String,
    pub topics: Value,
    #[serde(rename = "contractIds")]
    pub contract_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
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
    pub fn parsed(&self) -> Result<ParsedGetEvents, ()> {
        match (self.start_ledger, self.pagination.cursor.as_deref()) {
            (Some(_), Some(_)) | (None, None) => Err(()),
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

        if first.topics != json!([["**"]]) {
            return false;
        }

        let mut got: Vec<&str> = first.contract_ids.iter().map(String::as_str).collect();
        got.sort_unstable();
        let mut want: Vec<&str> = allowed_contract_ids.iter().map(String::as_str).collect();
        want.sort_unstable();
        got == want
    }
}

pub fn parse_get_events_params(params: &Value) -> anyhow::Result<ParsedGetEvents> {
    let params: GetEventsParams = serde_json::from_value(params.clone())?;
    params.parsed().map_err(|()| {
        anyhow::anyhow!("getEvents params must include either startLedger or pagination.cursor")
    })
}

pub fn is_allowed_filters(params: &Value, allowed_contract_ids: &[String]) -> bool {
    serde_json::from_value::<GetEventsParams>(params.clone())
        .map(|p| p.is_allowed_filters(allowed_contract_ids))
        .unwrap_or(false)
}

pub fn parse_get_events_result(result: &Value) -> anyhow::Result<(String, Vec<Value>, u32, u32)> {
    let cursor = result
        .get("cursor")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing cursor"))?
        .to_string();
    let events = result
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("getEvents result missing events"))?
        .clone();
    let latest_ledger = u32::try_from(
        result
            .get("latestLedger")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("getEvents result missing latestLedger"))?,
    )
    .map_err(|_| anyhow::anyhow!("getEvents latestLedger exceeds u32"))?;
    let oldest_ledger = u32::try_from(
        result
            .get("oldestLedger")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("getEvents result missing oldestLedger"))?,
    )
    .map_err(|_| anyhow::anyhow!("getEvents oldestLedger exceeds u32"))?;
    Ok((cursor, events, latest_ledger, oldest_ledger))
}

pub fn make_get_events_params(
    contract_ids: &[String],
    start_ledger: Option<u32>,
    cursor: Option<&str>,
    limit: u32,
) -> Value {
    let mut filters = serde_json::Map::new();
    filters.insert("type".to_string(), Value::String("contract".to_string()));
    filters.insert("topics".to_string(), json!([["**"]]));
    filters.insert("contractIds".to_string(), json!(contract_ids));

    let mut pagination = serde_json::Map::new();
    pagination.insert("limit".to_string(), json!(limit));
    if let Some(cursor) = cursor {
        pagination.insert("cursor".to_string(), Value::String(cursor.to_string()));
    }

    let mut params = json!({
        "filters": [Value::Object(filters)],
        "pagination": Value::Object(pagination),
    });

    if let Some(start) = start_ledger {
        params["startLedger"] = json!(start);
    }

    params
}
