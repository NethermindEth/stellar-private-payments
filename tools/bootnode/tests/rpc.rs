use bootnode::{get_events, rpc};
use serde_json::json;

#[test]
fn error_codes() {
    assert_eq!(rpc::cache_miss("miss").code(), rpc::CACHE_MISS_CODE);
    assert_eq!(
        rpc::retention_handoff(42_000).code(),
        rpc::RETENTION_HANDOFF_CODE
    );
}

#[test]
fn retention_handoff_shape() {
    let err = rpc::retention_handoff(42_000);
    let data = err.data().expect("expected error data");
    let data: serde_json::Value = serde_json::from_str(data.get()).expect("valid json data");
    assert_eq!(data["fromLedger"], 42_000);
    assert_eq!(data["reason"], "retention_threshold");
}

#[test]
fn make_get_events_params_shape() {
    let ids = vec!["CABC".to_string(), "CDEF".to_string()];
    let params = get_events::make_get_events_params(&ids, Some(100), Some("cursor-1"), 300);

    assert_eq!(params["startLedger"], 100);
    assert_eq!(params["pagination"]["limit"], 300);
    assert_eq!(params["pagination"]["cursor"], "cursor-1");
    assert_eq!(params["filters"][0]["type"], "contract");
    assert_eq!(params["filters"][0]["topics"], json!([["**"]]));
    assert_eq!(params["filters"][0]["contractIds"], json!(ids));
}
