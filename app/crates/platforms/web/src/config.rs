use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Config {
    rpc_url: String,
    indexer_rpc_url: Option<String>,
}

#[wasm_bindgen]
impl Config {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: String, indexer_rpc_url: Option<String>) -> Config {
        Config {
            rpc_url,
            indexer_rpc_url,
        }
    }
}

impl Config {
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn indexer_rpc_url(&self) -> &str {
        self.indexer_rpc_url.as_deref().unwrap_or(&self.rpc_url)
    }
}
