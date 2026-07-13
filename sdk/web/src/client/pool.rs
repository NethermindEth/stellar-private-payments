//! [`PrivatePool`] — per-pool session (Rust SDK high-level API).

use std::rc::Rc;

use stellar_private_payments_sdk::{
    DisclosureRequest, PrivatePool as SdkPrivatePool,
    types::{DisclosureReceipt, EncryptionPublicKey, NoteAmount, NotePublicKey, TransferRecipient},
};
use wasm_bindgen::prelude::*;

use crate::{
    client::{execute::emit, pool_err, transact::parse_transact_step},
    workers::storage::StorageBridge,
};

#[derive(Debug, Clone)]
pub(crate) struct PoolCreateConfig {
    pub pool_contract: String,
    pub user_address: String,
}

/// Per-pool session for deposits, transfers, and withdrawals.
#[wasm_bindgen]
pub struct PrivatePool {
    inner: Rc<SdkPrivatePool<StorageBridge>>,
    user_address: String,
}

impl PrivatePool {
    pub(crate) fn from_parts(
        inner: Rc<SdkPrivatePool<StorageBridge>>,
        user_address: String,
    ) -> Self {
        Self {
            inner,
            user_address,
        }
    }

    pub(crate) fn inner(&self) -> &SdkPrivatePool<StorageBridge> {
        &self.inner
    }
}

#[wasm_bindgen]
impl PrivatePool {
    pub async fn sync(&self) -> Result<(), JsError> {
        self.inner().sync().await.map_err(pool_err)
    }

    /// Balance in stroops (`bigint` in JS).
    #[wasm_bindgen(js_name = getBalance)]
    pub async fn get_balance(&self) -> Result<u128, JsError> {
        let amount = self.inner().balance().await.map_err(pool_err)?;
        Ok(u128::from(amount))
    }

    /// User notes for this pool (commitments, amounts, spent status).
    pub async fn notes(&self) -> Result<JsValue, JsError> {
        let notes = self.inner().notes().await.map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&notes)?)
    }

    /// Estimate how many on-chain transactions a spend of `amount` stroops
    /// would require.
    pub async fn estimate(&self, amount: u128) -> Result<JsValue, JsError> {
        let estimate = self
            .inner()
            .estimate(NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&estimate)?)
    }

    /// Deposit tokens. `amount` is stroops (`bigint` in JS).
    pub async fn deposit(&self, amount: u128) -> Result<JsValue, JsError> {
        let mut plan = self
            .inner()
            .prepare_deposit(NoteAmount::from(amount))
            .map_err(pool_err)?;
        self.execute_plan(&mut plan, "deposit").await
    }

    /// Transfer privately to explicit recipient keys (note + encryption hex).
    #[wasm_bindgen(js_name = transferToKeys)]
    pub async fn transfer_to_keys(
        &self,
        note_public_key_hex: &str,
        encryption_public_key_hex: &str,
        amount: u128,
    ) -> Result<JsValue, JsError> {
        let recipient = TransferRecipient::keys(
            NotePublicKey::parse(note_public_key_hex).map_err(|e| JsError::new(&e.to_string()))?,
            EncryptionPublicKey::parse(encryption_public_key_hex)
                .map_err(|e| JsError::new(&e.to_string()))?,
        );
        let wallet = self.inner().spendable_notes().await.map_err(pool_err)?;
        let mut plan = self
            .inner()
            .prepare_transfer(&wallet, recipient, NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        self.execute_plan(&mut plan, "transfer").await
    }

    /// Transfer privately. `recipient` is a Stellar `G...` address.
    pub async fn transfer(&self, recipient: &str, amount: u128) -> Result<JsValue, JsError> {
        let wallet = self.inner().spendable_notes().await.map_err(pool_err)?;
        let mut plan = self
            .inner()
            .prepare_transfer(&wallet, recipient, NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        self.execute_plan(&mut plan, "transfer").await
    }

    /// Withdraw to `recipient`, or the connected wallet when omitted.
    pub async fn withdraw(
        &self,
        amount: u128,
        recipient: Option<String>,
    ) -> Result<JsValue, JsError> {
        let to = recipient.unwrap_or_else(|| self.user_address.clone());
        let wallet = self.inner().spendable_notes().await.map_err(pool_err)?;
        let mut plan = self
            .inner()
            .prepare_withdraw(&wallet, NoteAmount::from(amount), to)
            .map_err(pool_err)?;
        self.execute_plan(&mut plan, "withdraw").await
    }

    /// Low-level pool `transact` call. See SDK [`Transact`] for field
    /// semantics.
    pub async fn transact(&self, config: JsValue) -> Result<JsValue, JsError> {
        let step = parse_transact_step(config)?;
        let mut plan = self.inner().prepare_transact(step);
        self.execute_plan(&mut plan, "transact").await
    }

    /// Generate a selective-disclosure proof for a note commitment.
    ///
    /// `config` matches [`DisclosureRequest`] (camelCase; `selectedCommitments`
    /// array with 1..=4 entries). Returns `null` when the account must register
    /// at the ASP before disclosing.
    pub async fn disclose(&self, config: JsValue) -> Result<JsValue, JsError> {
        let req: DisclosureRequest = serde_wasm_bindgen::from_value(config)?;
        emit("disclose", "prove", "Generating proof…", None, None);
        match self.inner().disclose(req).await.map_err(pool_err)? {
            None => Ok(JsValue::NULL),
            Some(receipt) => Ok(serde_wasm_bindgen::to_value(&receipt)?),
        }
    }

    #[wasm_bindgen(js_name = verifyDisclosure)]
    pub async fn verify_disclosure(
        &self,
        receipt: JsValue,
        expected_vk_hash: &str,
    ) -> Result<JsValue, JsError> {
        let receipt: DisclosureReceipt = serde_wasm_bindgen::from_value(receipt)?;
        let report = self
            .inner()
            .verify_disclosure(&receipt, expected_vk_hash)
            .await
            .map_err(pool_err)?;
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }
}
