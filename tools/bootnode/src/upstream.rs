use crate::messages::{GetEventsParams, GetEventsResponse, GetLatestLedgerResponse};
use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
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

    pub(crate) async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse> {
        self.rpc_call("getLatestLedger", json!({})).await
    }

    pub(crate) async fn get_events(&self, params: GetEventsParams) -> Result<GetEventsResponse> {
        self.rpc_call("getEvents", params).await
    }

    async fn rpc_call<T, P>(&self, method: &'static str, params: P) -> Result<T>
    where
        P: Serialize,
        T: DeserializeOwned,
    {
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
            .await
            .with_context(|| format!("upstream {method} request to {}", self.base_url))?
            .json()
            .await
            .context("failed to decode upstream JSON response")?;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("upstream jsonrpc error: {err}");
        }

        resp.get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("upstream response missing result field for {method}"))
            .and_then(|result| serde_json::from_value(result).map_err(Into::into))
    }
}
