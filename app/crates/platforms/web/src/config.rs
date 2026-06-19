use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Config {
    rpc_url: String,
    bootnode_url: Option<String>,
}

#[wasm_bindgen]
impl Config {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: String, bootnode_url: Option<String>) -> Config {
        Config {
            rpc_url,
            bootnode_url,
        }
    }
}

impl Config {
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn bootnode_url(&self) -> Option<&str> {
        self.bootnode_url.as_deref()
    }
}
