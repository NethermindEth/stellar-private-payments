use bootnode::get_events;
use serde_json::json;

fn sample_filters(ids: &[&str]) -> serde_json::Value {
    json!({
        "filters": [{
            "type": "contract",
            "topics": [["**"]],
            "contractIds": ids
        }]
    })
}

#[test]
fn parse_start_ledger() {
    let params = json!({"startLedger": 42, "pagination": {"limit": 100}});
    let parsed = get_events::parse_get_events_params(&params).unwrap();
    assert_eq!(parsed.start_ledger, Some(42));
    assert!(parsed.cursor.is_none());
    assert_eq!(parsed.limit, Some(100));
}

#[test]
fn parse_cursor() {
    let params = json!({"pagination": {"cursor": "abc", "limit": 50}});
    let parsed = get_events::parse_get_events_params(&params).unwrap();
    assert!(parsed.start_ledger.is_none());
    assert_eq!(parsed.cursor.as_deref(), Some("abc"));
    assert_eq!(parsed.limit, Some(50));
}

#[test]
fn reject_ambiguous_params() {
    let both = json!({"startLedger": 1, "pagination": {"cursor": "x"}});
    assert!(get_events::parse_get_events_params(&both).is_err());

    let neither = json!({"pagination": {"limit": 10}});
    assert!(get_events::parse_get_events_params(&neither).is_err());
}

#[test]
fn allowed_filters_match_exact_contract_set() {
    let allowed = vec!["CB".to_string(), "CA".to_string()];
    let params = sample_filters(&["CA", "CB"]);
    assert!(get_events::is_allowed_filters(&params, &allowed));
}

#[test]
fn reject_wrong_contract_ids_or_topics() {
    let allowed = vec!["CA".to_string()];
    assert!(!get_events::is_allowed_filters(
        &sample_filters(&["CA", "CB"]),
        &allowed
    ));
    assert!(!get_events::is_allowed_filters(
        &json!({"filters": [{"type": "contract", "topics": [["deposit"]], "contractIds": ["CA"]}]}),
        &allowed
    ));
}

#[test]
fn parse_upstream_result() {
    let result = json!({
        "cursor": "next",
        "events": [{"ledger": 10}],
        "latestLedger": 99,
        "oldestLedger": 1
    });
    let (cursor, events, latest, oldest) = get_events::parse_get_events_result(&result).unwrap();
    assert_eq!(cursor, "next");
    assert_eq!(events.len(), 1);
    assert_eq!(latest, 99);
    assert_eq!(oldest, 1);
}

#[test]
fn parse_result_requires_fields() {
    assert!(get_events::parse_get_events_result(&json!({})).is_err());
}
