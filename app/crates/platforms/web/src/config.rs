use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Config {
    rpc_url: String,
}

#[wasm_bindgen]
impl Config {
    #[wasm_bindgen(constructor)]
    pub fn new(rpc_url: String) -> Config {
        let url = rpc_url;
        Config { rpc_url: url }
    }
}


impl Config {
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}
