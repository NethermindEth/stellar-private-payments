use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: Option<String>,
    pub(crate) id: Option<Value>,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcResponse {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    pub(crate) result: Value,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcErrorResponse {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: Value,
    pub(crate) error: JsonRpcErrorObject,
}

#[derive(Debug, Serialize)]
pub(crate) struct JsonRpcErrorObject {
    pub(crate) code: i64,
    pub(crate) message: String,
}

pub(crate) fn ok(id: Value, result: Value) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result,
    }
}

pub(crate) fn err(id: Value, code: i64, message: impl Into<String>) -> JsonRpcErrorResponse {
    JsonRpcErrorResponse {
        jsonrpc: "2.0",
        id,
        error: JsonRpcErrorObject {
            code,
            message: message.into(),
        },
    }
}

pub(crate) fn null_id() -> Value {
    Value::Null
}

pub(crate) fn invalid_params(id: Value, msg: impl Into<String>) -> JsonRpcErrorResponse {
    err(id, -32602, msg)
}

pub(crate) fn method_not_found(id: Value) -> JsonRpcErrorResponse {
    err(id, -32601, "Method not found")
}

pub(crate) fn internal_error(id: Value, msg: impl Into<String>) -> JsonRpcErrorResponse {
    err(id, -32603, msg)
}

pub(crate) fn cache_miss(id: Value, msg: impl Into<String>) -> JsonRpcErrorResponse {
    err(id, -32004, msg)
}

pub(crate) fn parse_error(msg: impl Into<String>) -> JsonRpcErrorResponse {
    err(Value::Null, -32700, msg)
}

pub(crate) fn make_get_events_params(
    contract_ids: &[String],
    start_ledger: Option<u32>,
    cursor: Option<&str>,
    limit: u32,
) -> Value {
    let mut filters = serde_json::Map::new();
    filters.insert("type".to_string(), Value::String("contract".to_string()));
    filters.insert(
        "topics".to_string(),
        json!([[ "**" ]]),
    );
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

