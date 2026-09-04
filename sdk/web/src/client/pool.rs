//! [`PrivatePool`] — per-pool session (Rust SDK high-level API).

use std::{rc::Rc, str::FromStr};

use stellar_private_payments::{
    PrivatePool as NativePrivatePool,
    types::{EncryptionPublicKey, Field, NoteAmount, NotePublicKey, TransferRecipient},
};
use wasm_bindgen::prelude::*;

use crate::{
    client::{execute::emit, gvk::GvkAudit, pool_err},
    correlation::{new_correlation_id, with_correlation_id},
    models::{
        DisclosureReceipt, DisclosureRequest, DisclosureVerificationReport, PoolEstimate,
        PoolExecuteResult, UserNoteSummary, transact_from_js, user_note_summaries,
    },
    workers::storage::StorageBridge,
};

/// Per-pool session for deposits, transfers, and withdrawals.
#[wasm_bindgen]
pub struct PrivatePool {
    inner: Rc<NativePrivatePool<StorageBridge>>,
    user_address: String,
}

impl PrivatePool {
    pub(crate) fn from_parts(
        inner: Rc<NativePrivatePool<StorageBridge>>,
        user_address: String,
    ) -> Self {
        Self {
            inner,
            user_address,
        }
    }

    pub(crate) fn inner(&self) -> &NativePrivatePool<StorageBridge> {
        &self.inner
    }
}

#[wasm_bindgen]
impl PrivatePool {
    /// Balance in stroops (`bigint` in JS).
    pub async fn balance(&self) -> Result<u128, JsError> {
        let amount = self.inner().balance().await.map_err(pool_err)?;
        Ok(u128::from(amount))
    }

    /// User notes for this pool (commitments, amounts, spent status).
    pub async fn notes(&self) -> Result<Vec<UserNoteSummary>, JsError> {
        let notes = self.inner().notes().await.map_err(pool_err)?;
        Ok(user_note_summaries(notes))
    }

    /// Estimate how many on-chain transactions a spend of `amount` stroops
    /// would require.
    pub async fn estimate(&self, amount: u128) -> Result<PoolEstimate, JsError> {
        let estimate = self
            .inner()
            .estimate(NoteAmount::from(amount))
            .await
            .map_err(pool_err)?;
        Ok(PoolEstimate::from(estimate))
    }

    /// Deposit tokens. `amount` is stroops (`bigint` in JS).
    pub async fn deposit(&self, amount: u128) -> Result<PoolExecuteResult, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let mut plan = self
                .inner()
                .prepare_deposit(NoteAmount::from(amount))
                .map_err(pool_err)?;
            self.execute_plan(&mut plan, "deposit").await
        })
        .await
    }

    /// Transfer privately to explicit recipient keys (note + encryption hex).
    #[wasm_bindgen(js_name = transferToKeys)]
    pub async fn transfer_to_keys(
        &self,
        note_public_key_hex: &str,
        encryption_public_key_hex: &str,
        amount: u128,
    ) -> Result<PoolExecuteResult, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let recipient = TransferRecipient::keys(
                NotePublicKey::parse(note_public_key_hex)
                    .map_err(|e| JsError::new(&e.to_string()))?,
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
        })
        .await
    }

    /// Transfer privately. `recipient` is a Stellar `G...` address.
    pub async fn transfer(
        &self,
        recipient: &str,
        amount: u128,
    ) -> Result<PoolExecuteResult, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let wallet = self.inner().spendable_notes().await.map_err(pool_err)?;
            let mut plan = self
                .inner()
                .prepare_transfer(&wallet, recipient, NoteAmount::from(amount))
                .await
                .map_err(pool_err)?;
            self.execute_plan(&mut plan, "transfer").await
        })
        .await
    }

    /// Withdraw to `recipient`, or the connected wallet when omitted.
    pub async fn withdraw(
        &self,
        amount: u128,
        recipient: Option<String>,
    ) -> Result<PoolExecuteResult, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let to = recipient.unwrap_or_else(|| self.user_address.clone());
            let wallet = self.inner().spendable_notes().await.map_err(pool_err)?;
            let mut plan = self
                .inner()
                .prepare_withdraw(&wallet, NoteAmount::from(amount), to)
                .map_err(pool_err)?;
            self.execute_plan(&mut plan, "withdraw").await
        })
        .await
    }

    /// Low-level pool `transact` call. See SDK [`Transact`] for field
    /// semantics.
    pub async fn transact(&self, config: JsValue) -> Result<PoolExecuteResult, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let step = transact_from_js(config)?;
            let mut plan = self.inner().prepare_transact(step);
            self.execute_plan(&mut plan, "transact").await
        })
        .await
    }

    /// Generate a selective-disclosure proof for a note commitment.
    ///
    /// Returns `undefined` when the account must register at the ASP before
    /// disclosing; check with `== null`.
    pub async fn disclose(
        &self,
        req: &DisclosureRequest,
    ) -> Result<Option<DisclosureReceipt>, JsError> {
        with_correlation_id(new_correlation_id(), async {
            emit("disclose", "prove", "Generating proof…", None, None);
            match self
                .inner()
                .disclose(req.native())
                .await
                .map_err(pool_err)?
            {
                None => Ok(None),
                Some(receipt) => Ok(Some(DisclosureReceipt::from(receipt))),
            }
        })
        .await
    }

    #[wasm_bindgen(js_name = verifyDisclosure)]
    pub async fn verify_disclosure(
        &self,
        receipt: &DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<DisclosureVerificationReport, JsError> {
        with_correlation_id(new_correlation_id(), async {
            let report = self
                .inner()
                .verify_disclosure(receipt.native(), expected_vk_hash)
                .await
                .map_err(pool_err)?;
            Ok(DisclosureVerificationReport::from(report))
        })
        .await
    }

    /// Open an admin audit cursor for this pool.
    ///
    /// `globalViewPrivateKeyHex` is the admin authority scalar as a
    /// `0x`-prefixed field hex string. Requires a pool-gvk deployment with
    /// GVK enabled.
    pub async fn audit(&self, global_view_private_key_hex: &str) -> Result<GvkAudit, JsError> {
        let d_priv = Field::from_str(global_view_private_key_hex.trim())
            .map_err(|e| JsError::new(&e.to_string()))?;
        let inner = self.inner().audit(d_priv).await.map_err(pool_err)?;
        Ok(GvkAudit::new(inner))
    }
}
