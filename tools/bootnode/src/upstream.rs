use anyhow::Result;
use serde_json::json;
use url::Url;

#[derive(Clone)]
pub(crate) struct UpstreamClient {
    base_url: Url,
    http: reqwest::Client,
}

impl UpstreamClient {
    pub(crate) fn new(base_url: Url) -> Result<Self> {
        Ok(Self {
            base_url,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    pub(crate) async fn get_latest_ledger(&self) -> Result<serde_json::Value> {
        self.rpc_call("getLatestLedger", json!({})).await
    }

    pub(crate) async fn get_events(&self, params: serde_json::Value) -> Result<serde_json::Value> {
        self.rpc_call("getEvents", params).await
    }

    async fn rpc_call(&self, method: &'static str, params: serde_json::Value) -> Result<serde_json::Value> {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let resp: serde_json::Value = self
            .http
            .post(self.base_url.clone())
            .json(&payload)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("upstream jsonrpc error: {err}");
        }

        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("upstream response missing result field for {method}"))
    }
}

