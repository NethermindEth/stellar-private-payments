use bootnode::jsonrpc;
use serde_json::json;

#[test]
fn ok_wraps_result() {
    let resp = jsonrpc::ok(json!(1), json!({"sequence": 42}));
    assert_eq!(resp.jsonrpc, "2.0");
    assert_eq!(resp.id, json!(1));
    assert_eq!(resp.result["sequence"], 42);
}

#[test]
fn error_codes() {
    let id = json!(1);
    assert_eq!(jsonrpc::method_not_found(id.clone()).error.code, -32601);
    assert_eq!(
        jsonrpc::invalid_params(id.clone(), "bad").error.code,
        -32602
    );
    assert_eq!(jsonrpc::cache_miss(id, "miss").error.code, -32004);
    assert_eq!(jsonrpc::parse_error("bad json").error.code, -32700);
}

#[test]
fn make_get_events_params_shape() {
    let ids = vec!["CABC".to_string(), "CDEF".to_string()];
    let params = jsonrpc::make_get_events_params(&ids, Some(100), Some("cursor-1"), 300);

    assert_eq!(params["startLedger"], 100);
    assert_eq!(params["pagination"]["limit"], 300);
    assert_eq!(params["pagination"]["cursor"], "cursor-1");
    assert_eq!(params["filters"][0]["type"], "contract");
    assert_eq!(params["filters"][0]["topics"], json!([["**"]]));
    assert_eq!(params["filters"][0]["contractIds"], json!(ids));
}
