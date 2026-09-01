use std::collections::BTreeMap;

use stellar_private_payments::types::{
    AssetDescriptor as NativeAssetDescriptor, ContractConfig as NativeContractConfig,
    PoolConfigEntry as NativePoolConfigEntry,
};
use wasm_bindgen::prelude::*;

use super::{
    baby_jubjub_point::BabyJubJubPoint,
    convert::{gvk_mode_name, policy_flag_names},
};

#[wasm_bindgen]
pub struct AssetDescriptor {
    inner: NativeAssetDescriptor,
}

#[wasm_bindgen]
impl AssetDescriptor {
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        match self.inner {
            NativeAssetDescriptor::Native => "native".to_string(),
            NativeAssetDescriptor::Classic { .. } => "classic".to_string(),
            NativeAssetDescriptor::Contract { .. } => "contract".to_string(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<String> {
        match &self.inner {
            NativeAssetDescriptor::Classic { code, .. } => Some(code.clone()),
            _ => None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn issuer(&self) -> Option<String> {
        match &self.inner {
            NativeAssetDescriptor::Classic { issuer, .. } => Some(issuer.clone()),
            _ => None,
        }
    }

    #[wasm_bindgen(getter, js_name = contractId)]
    pub fn contract_id(&self) -> Option<String> {
        match &self.inner {
            NativeAssetDescriptor::Contract { contract_id, .. } => Some(contract_id.clone()),
            _ => None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn symbol(&self) -> Option<String> {
        match &self.inner {
            NativeAssetDescriptor::Contract { symbol, .. } => Some(symbol.clone()),
            _ => None,
        }
    }
}

impl From<NativeAssetDescriptor> for AssetDescriptor {
    fn from(inner: NativeAssetDescriptor) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct VerifierEntry {
    suffix: String,
    address: String,
}

#[wasm_bindgen]
impl VerifierEntry {
    #[wasm_bindgen(getter)]
    pub fn suffix(&self) -> String {
        self.suffix.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn address(&self) -> String {
        self.address.clone()
    }
}

fn verifier_entries(map: &BTreeMap<String, String>) -> Vec<VerifierEntry> {
    map.iter()
        .map(|(suffix, address)| VerifierEntry {
            suffix: suffix.clone(),
            address: address.clone(),
        })
        .collect()
}

#[wasm_bindgen]
pub struct PoolConfigEntry {
    inner: NativePoolConfigEntry,
}

#[wasm_bindgen]
impl PoolConfigEntry {
    #[wasm_bindgen(getter, js_name = poolContractId)]
    pub fn pool_contract_id(&self) -> String {
        self.inner.pool_contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = tokenContractId)]
    pub fn token_contract_id(&self) -> String {
        self.inner.token_contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = deploymentLedger)]
    pub fn deployment_ledger(&self) -> u32 {
        self.inner.deployment_ledger
    }

    #[wasm_bindgen(getter)]
    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }

    #[wasm_bindgen(getter)]
    pub fn asset(&self) -> AssetDescriptor {
        AssetDescriptor::from(self.inner.asset.clone())
    }

    #[wasm_bindgen(getter, js_name = policyFlags)]
    pub fn policy_flags(&self) -> Vec<String> {
        policy_flag_names(self.inner.policy_flags)
    }

    #[wasm_bindgen(getter, js_name = gvkMode)]
    pub fn gvk_mode(&self) -> String {
        gvk_mode_name(self.inner.gvk_mode).to_string()
    }

    #[wasm_bindgen(getter, js_name = gvkAuthorityPubKey)]
    pub fn gvk_authority_pub_key(&self) -> Option<BabyJubJubPoint> {
        self.inner
            .gvk_authority_pub_key
            .as_ref()
            .map(BabyJubJubPoint::from)
    }
}

impl From<NativePoolConfigEntry> for PoolConfigEntry {
    fn from(inner: NativePoolConfigEntry) -> Self {
        Self { inner }
    }
}

#[wasm_bindgen]
pub struct ContractConfig {
    inner: NativeContractConfig,
}

#[wasm_bindgen]
impl ContractConfig {
    #[wasm_bindgen(constructor)]
    pub fn new(value: JsValue) -> Result<ContractConfig, JsError> {
        contract_config_from_js(value)
    }

    #[wasm_bindgen(getter)]
    pub fn network(&self) -> String {
        self.inner.network.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn deployer(&self) -> String {
        self.inner.deployer.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn admin(&self) -> String {
        self.inner.admin.clone()
    }

    #[wasm_bindgen(getter, js_name = asp_membership)]
    pub fn asp_membership(&self) -> String {
        self.inner.asp_membership.clone()
    }

    #[wasm_bindgen(getter, js_name = asp_non_membership)]
    pub fn asp_non_membership(&self) -> String {
        self.inner.asp_non_membership.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn verifiers(&self) -> Vec<VerifierEntry> {
        verifier_entries(&self.inner.verifiers)
    }

    #[wasm_bindgen(getter, js_name = public_key_registry)]
    pub fn public_key_registry(&self) -> String {
        self.inner.public_key_registry.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pools(&self) -> Vec<PoolConfigEntry> {
        self.inner
            .pools
            .iter()
            .cloned()
            .map(PoolConfigEntry::from)
            .collect()
    }

    /// Plain JSON object matching `deployments.json` (for round-trip input).
    #[wasm_bindgen(js_name = toJSON)]
    pub fn to_json(&self) -> Result<JsValue, JsError> {
        let json = serde_json::to_value(self.native())
            .map_err(|e| JsError::new(&format!("failed to serialize contractConfig: {e}")))?;
        serde_wasm_bindgen::to_value(&json)
            .map_err(|e| JsError::new(&format!("failed to convert contractConfig: {e}")))
    }

    pub(crate) fn native(&self) -> &NativeContractConfig {
        &self.inner
    }
}

impl From<NativeContractConfig> for ContractConfig {
    fn from(inner: NativeContractConfig) -> Self {
        Self { inner }
    }
}

pub(crate) fn contract_config_from_js(value: JsValue) -> Result<ContractConfig, JsError> {
    if value.is_null() || value.is_undefined() {
        return Err(JsError::new("contractConfig is required"));
    }
    if is_bindgen_contract_config(&value) {
        return contract_config_from_bindgen_js(&value);
    }
    let inner: NativeContractConfig = serde_wasm_bindgen::from_value(value)
        .map_err(|e| JsError::new(&format!("invalid contractConfig: {e}")))?;
    Ok(ContractConfig::from(inner))
}

/// Bindgen [`ContractConfig`] exposes `verifiers` as an array; deployments.json
/// uses an object.
fn is_bindgen_contract_config(value: &JsValue) -> bool {
    js_sys::Reflect::get(value, &JsValue::from_str("verifiers"))
        .ok()
        .is_some_and(|v| js_sys::Array::is_array(&v))
}

fn contract_config_from_bindgen_js(value: &JsValue) -> Result<ContractConfig, JsError> {
    let to_json = js_sys::Reflect::get(value, &JsValue::from_str("toJSON"))
        .map_err(|_| JsError::new("ContractConfig instance missing toJSON"))?;
    let func = to_json
        .dyn_ref::<js_sys::Function>()
        .ok_or_else(|| JsError::new("ContractConfig.toJSON is not callable"))?;
    let plain = func
        .call0(value)
        .map_err(|_| JsError::new("ContractConfig.toJSON failed"))?;
    let inner: NativeContractConfig = serde_wasm_bindgen::from_value(plain)
        .map_err(|e| JsError::new(&format!("invalid contractConfig: {e}")))?;
    Ok(ContractConfig::from(inner))
}
