use bootnode::rpc;

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
