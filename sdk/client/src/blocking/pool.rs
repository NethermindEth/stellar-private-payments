//! Sync wrapper around [`crate::PrivatePool`] via a shared Tokio runtime.

use tx_planner::SpendableNote;
use types::{EncryptionPublicKey, NoteAmount, NotePublicKey, UserNoteSummary};

use crate::{
    PreparedTransaction, PreparedTransactionPlan,
    error::Error,
    pool::PrivatePool as AsyncPrivatePool,
    storage::LocalStorage,
    types::{Estimate, PrivatePoolConfig, SignedTransaction, TransactionResult, TransferRecipient},
};

use super::runtime::block_on;

/// Native sync wallet — [`crate::PrivatePool`] with blocking method names.
///
/// Construct via [`super::Client::account`] → [`super::Account::pool`].
pub struct PrivatePool {
    inner: AsyncPrivatePool<LocalStorage>,
}

impl PrivatePool {
    pub(crate) fn from_inner(inner: AsyncPrivatePool<LocalStorage>) -> Self {
        Self { inner }
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        self.inner.config()
    }

    pub fn estimate(&self, amount: NoteAmount) -> Result<Estimate, Error> {
        block_on(self.inner.estimate(amount))
    }

    pub fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, Error> {
        block_on(self.inner.deposit(amount))
    }

    pub fn transfer(
        &self,
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, Error> {
        block_on(self.inner.transfer(recipient, amount))
    }

    pub fn withdraw(
        &self,
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, Error> {
        block_on(self.inner.withdraw(amount, recipient))
    }

    pub fn transact(&self, step: tx_planner::Transact) -> Result<TransactionResult, Error> {
        block_on(self.inner.transact(step))
    }

    pub fn sync(&self) -> Result<(), Error> {
        block_on(self.inner.sync())
    }

    pub fn prepare_deposit(&self, amount: NoteAmount) -> Result<PreparedTransactionPlan, Error> {
        self.inner.prepare_deposit(amount)
    }

    pub fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: impl Into<TransferRecipient>,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        block_on(self.inner.prepare_transfer(wallet, recipient, amount))
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, Error> {
        self.inner.prepare_withdraw(wallet, amount, recipient)
    }

    pub fn prepare_transact(&self, step: tx_planner::Transact) -> PreparedTransactionPlan {
        self.inner.prepare_transact(step)
    }

    pub fn prove_next(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, Error> {
        block_on(self.inner.prove_next(plan))
    }

    pub fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, Error> {
        block_on(self.inner.sign(prepared))
    }

    pub fn spendable_notes(&self) -> Result<Vec<SpendableNote>, Error> {
        block_on(self.inner.spendable_notes())
    }

    pub fn notes(&self) -> Result<Vec<UserNoteSummary>, Error> {
        block_on(self.inner.notes())
    }

    pub fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), Error> {
        block_on(self.inner.user_public_keys(user_address))
    }

    pub fn balance(&self) -> Result<NoteAmount, Error> {
        block_on(self.inner.balance())
    }

    pub fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), Error> {
        block_on(self.inner.simulate(prepared))
    }

    pub fn submit(&self, signed_tx: SignedTransaction) -> Result<String, Error> {
        block_on(self.inner.submit(signed_tx))
    }

    pub fn confirm(&self, hash: &str) -> Result<TransactionResult, Error> {
        block_on(self.inner.confirm(hash))
    }

    pub fn disclose(
        &self,
        req: crate::DisclosureRequest,
    ) -> Result<Option<types::DisclosureReceipt>, Error> {
        block_on(self.inner.disclose(req))
    }

    pub fn verify_disclosure(
        &self,
        receipt: &types::DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<types::DisclosureVerificationReport, Error> {
        block_on(self.inner.verify_disclosure(receipt, expected_vk_hash))
    }
}
