use serde::{Deserialize, Deserializer, Serialize};

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

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct GetLatestLedgerResponse {
    pub id: String,
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    pub sequence: u32,
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
    #[serde(
        rename = "inSuccessfulContractCall",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub is_successful_contract_call: Option<bool>,

    pub topic: Vec<String>,
    pub value: String,
}

fn deserialize_default_from_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn for_contracts_serializes_roundtrip() {
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
    fn get_events_response_deserializes_null_events() {
        let response: GetEventsResponse = serde_json::from_value(json!({
            "events": null,
            "latestLedger": 10,
            "latestLedgerCloseTime": "t",
            "oldestLedger": 1,
            "oldestLedgerCloseTime": "t",
            "cursor": "c",
        }))
        .expect("response should deserialize");
        assert!(response.events.is_empty());
    }
}
