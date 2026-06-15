use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedGetEvents {
    pub start_ledger: Option<u32>,
    pub cursor: Option<String>,
    pub limit: Option<u32>,
}

pub fn parse_get_events_params(params: &Value) -> anyhow::Result<ParsedGetEvents> {
    let start_ledger = params
        .get("startLedger")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    let pagination = params.get("pagination").and_then(|v| v.as_object());
    let limit = pagination
        .and_then(|p| p.get("limit"))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok());
    let cursor = pagination
        .and_then(|p| p.get("cursor"))
        .and_then(|v| v.as_str())
        .map(str::to_owned);

    match (start_ledger, cursor) {
        (Some(_), Some(_)) | (None, None) => {
            anyhow::bail!("getEvents params must include either startLedger or pagination.cursor")
        }
        (start_ledger, cursor) => Ok(ParsedGetEvents {
            start_ledger,
            cursor,
            limit,
        }),
    }
}

pub fn is_allowed_filters(params: &Value, allowed_contract_ids: &[String]) -> bool {
    let filters = params.get("filters").and_then(|v| v.as_array());
    let Some(filters) = filters else {
        return false;
    };
    let Some(first) = filters.first().and_then(|v| v.as_object()) else {
        return false;
    };

    if first.get("type").and_then(|v| v.as_str()) != Some("contract") {
        return false;
    }

    if first.get("topics") != Some(&serde_json::json!([["**"]])) {
        return false;
    }

    let contract_ids = first.get("contractIds").and_then(|v| v.as_array());
    let Some(contract_ids) = contract_ids else {
        return false;
    };
    let mut got: Vec<&str> = contract_ids.iter().filter_map(|v| v.as_str()).collect();
    got.sort_unstable();
    let mut want: Vec<&str> = allowed_contract_ids.iter().map(String::as_str).collect();
    want.sort_unstable();
    got == want
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
