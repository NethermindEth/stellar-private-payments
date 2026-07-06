//! Sync wrapper around [`crate::PrivatePool`] via a shared Tokio runtime.

use tx_planner::SpendableNote;
use types::{EncryptionPublicKey, NoteAmount, NotePublicKey, UserNoteSummary};

use crate::{
    PreparedTransaction, PreparedTransactionPlan, SyncMode,
    error::PoolError,
    pool::PrivatePool as AsyncPrivatePool,
    prover::{LocalProver, NoopProver},
    signer::Signer,
    storage::LocalStorage,
    types::{Estimate, PrivatePoolConfig, SignedTransaction, TransactionResult, TransferRecipient},
};

use super::runtime::block_on;

/// Native sync wallet — [`crate::PrivatePool`] with blocking method names.
pub struct PrivatePool {
    inner: AsyncPrivatePool<LocalStorage>,
}

impl PrivatePool {
    pub fn open(config: PrivatePoolConfig, signer: Box<dyn Signer>) -> Result<Self, PoolError> {
        let storage = LocalStorage::open(&config.storage_path)?;
        let prover = Box::new(LocalProver::from_artifacts(&config.prover_artifacts)?);
        let inner = AsyncPrivatePool::init(config, storage, signer, prover, SyncMode::Inline)?;
        Ok(Self { inner })
    }

    /// Open a read-only pool session: no prover is constructed, so the proving
    /// key / circuit artifacts in `config.prover_artifacts` are ignored and
    /// never loaded. Suitable for balance/notes/sync; any transact/prove call
    /// on the resulting pool errors. Callers that only read state should use
    /// this to avoid the [`LocalProver`] init cost.
    pub fn open_readonly(
        config: PrivatePoolConfig,
        signer: Box<dyn Signer>,
    ) -> Result<Self, PoolError> {
        let storage = LocalStorage::open(&config.storage_path)?;
        let inner = AsyncPrivatePool::init(
            config,
            storage,
            signer,
            Box::new(NoopProver),
            SyncMode::Inline,
        )?;
        Ok(Self { inner })
    }

    /// Open against pre-populated local storage without inline RPC catch-up.
    ///
    /// Use for seeded databases and other callers that keep storage current
    /// separately (same contract as [`SyncMode::Background`]).
    pub fn open_local(
        config: PrivatePoolConfig,
        signer: Box<dyn Signer>,
    ) -> Result<Self, PoolError> {
        let storage = LocalStorage::open(&config.storage_path)?;
        let prover = Box::new(LocalProver::from_artifacts(&config.prover_artifacts)?);
        let inner = AsyncPrivatePool::init(config, storage, signer, prover, SyncMode::Background)?;
        Ok(Self { inner })
    }

    pub fn into_inner(self) -> AsyncPrivatePool<LocalStorage> {
        self.inner
    }

    pub fn inner(&self) -> &AsyncPrivatePool<LocalStorage> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut AsyncPrivatePool<LocalStorage> {
        &mut self.inner
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        self.inner.config()
    }

    pub fn estimate(&self, amount: NoteAmount) -> Result<Estimate, PoolError> {
        block_on(self.inner.estimate(amount))
    }

    pub fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        block_on(self.inner.deposit(amount))
    }

    pub fn transfer(
        &self,
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        block_on(self.inner.transfer(recipient, amount))
    }

    pub fn withdraw(
        &self,
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        block_on(self.inner.withdraw(amount, recipient))
    }

    pub fn transact(&self, step: tx_planner::Transact) -> Result<TransactionResult, PoolError> {
        block_on(self.inner.transact(step))
    }

    pub fn sync(&self) -> Result<(), PoolError> {
        block_on(self.inner.sync())
    }

    pub fn prepare_deposit(
        &self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.inner.prepare_deposit(amount)
    }

    pub fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.inner.prepare_transfer(wallet, recipient, amount)
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        self.inner.prepare_withdraw(wallet, amount, recipient)
    }

    pub fn prepare_transact(&self, step: tx_planner::Transact) -> PreparedTransactionPlan {
        self.inner.prepare_transact(step)
    }

    pub fn prove_next(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        block_on(self.inner.prove_next(plan))
    }

    pub fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, PoolError> {
        block_on(self.inner.sign(prepared))
    }

    pub fn spendable_notes(&self) -> Result<Vec<SpendableNote>, PoolError> {
        block_on(self.inner.spendable_notes())
    }

    pub fn notes(&self) -> Result<Vec<UserNoteSummary>, PoolError> {
        block_on(self.inner.notes())
    }

    pub fn user_public_keys(
        &self,
        user_address: &str,
    ) -> Result<(NotePublicKey, EncryptionPublicKey), PoolError> {
        block_on(self.inner.user_public_keys(user_address))
    }

    pub fn balance(&self) -> Result<NoteAmount, PoolError> {
        block_on(self.inner.balance())
    }

    pub fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        block_on(self.inner.simulate(prepared))
    }

    pub fn submit(&self, signed_tx: SignedTransaction) -> Result<String, PoolError> {
        block_on(self.inner.submit(signed_tx))
    }

    pub fn confirm(&self, hash: &str) -> Result<TransactionResult, PoolError> {
        block_on(self.inner.confirm(hash))
    }

    pub fn disclose(
        &self,
        req: crate::DisclosureRequest,
    ) -> Result<Option<types::DisclosureReceipt>, PoolError> {
        block_on(self.inner.disclose(req))
    }

    pub fn verify_disclosure(
        &self,
        receipt: &types::DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<types::DisclosureVerificationReport, PoolError> {
        block_on(self.inner.verify_disclosure(receipt, expected_vk_hash))
    }
}
