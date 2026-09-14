use stellar_private_payments::types::PortfolioBalance as NativePortfolioBalance;
use wasm_bindgen::prelude::*;

use super::convert::note_amount_string;

/// One pool balance row from [`crate::Account::portfolio`].
#[wasm_bindgen]
pub struct PortfolioBalance {
    inner: NativePortfolioBalance,
}

#[wasm_bindgen]
impl PortfolioBalance {
    #[wasm_bindgen(getter, js_name = poolContractId)]
    pub fn pool_contract_id(&self) -> String {
        self.inner.pool_contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = tokenContractId)]
    pub fn token_contract_id(&self) -> String {
        self.inner.token_contract_id.clone()
    }

    #[wasm_bindgen(getter, js_name = tokenLabel)]
    pub fn token_label(&self) -> String {
        self.inner.token_label.clone()
    }

    /// Stroops as a decimal string.
    #[wasm_bindgen(getter)]
    pub fn amount(&self) -> String {
        note_amount_string(&self.inner.amount)
    }

    #[wasm_bindgen(getter, js_name = noteCount)]
    pub fn note_count(&self) -> u32 {
        self.inner.note_count
    }
}

impl From<NativePortfolioBalance> for PortfolioBalance {
    fn from(inner: NativePortfolioBalance) -> Self {
        Self { inner }
    }
}

pub(crate) fn portfolio_balances(values: Vec<NativePortfolioBalance>) -> Vec<PortfolioBalance> {
    values.into_iter().map(PortfolioBalance::from).collect()
}
