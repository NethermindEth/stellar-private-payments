//! [`PrivatePool`] — per-pool session (Rust SDK high-level API).

use std::rc::Rc;

use stellar_private_payments_sdk::{
    DisclosureRequest, PrivatePool as SdkPrivatePool, PrivatePoolConfig,
    types::{
        ContractConfig, DisclosureReceipt, EncryptionPublicKey, NoteAmount, NotePublicKey,
        TransactionResult, TransferRecipient,
    },
};
use wasm_bindgen::prelude::*;

use crate::{
    client::{core::ClientCore, pool_err, transact::parse_transact_step},
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
    core: Rc<ClientCore>,
    user_address: String,
}

impl PrivatePool {
    pub(crate) fn from_parts(
        inner: Rc<SdkPrivatePool<StorageBridge>>,
        core: Rc<ClientCore>,
        user_address: String,
    ) -> Self {
        Self {
            inner,
            core,
            user_address,
        }
    }

    pub(crate) fn inner(&self) -> &SdkPrivatePool<StorageBridge> {
        &self.inner
    }

    async fn resolve_recipient(&self, recipient: &str) -> Result<(String, String), JsError> {
        if recipient.starts_with('G') {
            return self.core.recipient_keys(recipient).await;
        }
        Err(JsError::new(
            "recipient must be a Stellar address (G...); lookup uses the on-chain public key registry",
        ))
    }

    fn tx_results_to_js(results: Vec<TransactionResult>) -> Result<JsValue, JsError> {
        Ok(serde_wasm_bindgen::to_value(&results)?)
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
        self.sync().await?;
        let result = self
            .inner()
            .deposit(NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        self.sync().await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    /// Transfer privately to explicit recipient keys (note + encryption hex).
    #[wasm_bindgen(js_name = transferToKeys)]
    pub async fn transfer_to_keys(
        &self,
        note_public_key_hex: &str,
        encryption_public_key_hex: &str,
        amount: u128,
    ) -> Result<JsValue, JsError> {
        self.sync().await?;
        let recipient = TransferRecipient {
            note_public_key: NotePublicKey::parse(note_public_key_hex)
                .map_err(|e| JsError::new(&e.to_string()))?,
            encryption_public_key: EncryptionPublicKey::parse(encryption_public_key_hex)
                .map_err(|e| JsError::new(&e.to_string()))?,
        };
        let results = self
            .inner()
            .transfer(recipient, NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        self.sync().await?;
        Self::tx_results_to_js(results)
    }

    /// Transfer privately. `recipient` is a Stellar `G...` address.
    pub async fn transfer(&self, recipient: &str, amount: u128) -> Result<JsValue, JsError> {
        self.sync().await?;
        let (note_key, enc_key) = self.resolve_recipient(recipient).await?;
        let recipient = TransferRecipient {
            note_public_key: NotePublicKey::parse(&note_key)
                .map_err(|e| JsError::new(&e.to_string()))?,
            encryption_public_key: EncryptionPublicKey::parse(&enc_key)
                .map_err(|e| JsError::new(&e.to_string()))?,
        };
        let results = self
            .inner()
            .transfer(recipient, NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        self.sync().await?;
        Self::tx_results_to_js(results)
    }

    /// Withdraw to `recipient`, or the connected wallet when omitted.
    pub async fn withdraw(
        &self,
        amount: u128,
        recipient: Option<String>,
    ) -> Result<JsValue, JsError> {
        self.sync().await?;
        let to = recipient.unwrap_or_else(|| self.user_address.clone());
        let results = self
            .inner()
            .withdraw(NoteAmount::from(amount), to)
            .await
            .map_err(pool_err)?;
        self.sync().await?;
        Self::tx_results_to_js(results)
    }

    /// Low-level pool `transact` call. See SDK [`Transact`] for field
    /// semantics.
    pub async fn transact(&self, config: JsValue) -> Result<JsValue, JsError> {
        self.sync().await?;
        let step = parse_transact_step(config)?;
        let result = self.inner().transact(step).await.map_err(pool_err)?;
        self.sync().await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    /// Generate a selective-disclosure proof for a note commitment.
    ///
    /// `config` matches [`DisclosureRequest`] (camelCase). Returns `null` when
    /// the account must register at the ASP before disclosing.
    pub async fn disclose(&self, config: JsValue) -> Result<JsValue, JsError> {
        let req: DisclosureRequest = serde_wasm_bindgen::from_value(config)?;
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

pub(crate) fn build_pool_config(
    rpc_url: String,
    contract_config: ContractConfig,
    pool_contract_id: String,
    user_address: String,
) -> PrivatePoolConfig {
    PrivatePoolConfig {
        rpc_url,
        contract_config,
        pool_contract_id,
        user_address,
        storage_path: String::new(),
        prover_artifacts: stellar_private_payments_sdk::ProverArtifacts::empty(),
    }
}
