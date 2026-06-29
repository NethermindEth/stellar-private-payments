//! Sync wrapper around [`crate::PrivatePool`] via pollster.

use tx_planner::SpendableNote;
use types::{NoteAmount, UserNoteSummary};

use crate::{
    PreparedTransaction, PreparedTransactionPlan,
    error::PoolError,
    pool::PrivatePool as AsyncPrivatePool,
    prover::LocalProver,
    signer::Signer,
    storage::LocalStorage,
    types::{Estimate, PrivatePoolConfig, SignedTransaction, TransactionResult, TransferRecipient},
};

/// Native sync wallet — [`AsyncPrivatePool`] with blocking method names.
pub struct PrivatePool {
    inner: AsyncPrivatePool<LocalStorage>,
}

impl PrivatePool {
    pub fn open(config: PrivatePoolConfig, signer: Box<dyn Signer>) -> Result<Self, PoolError> {
        let storage = LocalStorage::open(&config.storage_path)?;
        let prover = Box::new(LocalProver::from_artifacts(&config.prover_artifacts)?);
        let inner = AsyncPrivatePool::init(config, storage, signer, prover)?;
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
        pollster::block_on(self.inner.estimate(amount))
    }

    pub fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.inner.deposit(amount))
    }

    pub fn transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.inner.transfer(wallet, recipient, amount))
    }

    pub fn withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.inner.withdraw(wallet, amount, recipient))
    }

    pub fn transact(&self, step: tx_planner::Transact) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.inner.transact(step))
    }

    pub fn sync(&self) -> Result<(), PoolError> {
        pollster::block_on(self.inner.sync())
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
        pollster::block_on(self.inner.prove_next(plan))
    }

    pub fn sign(&self, prepared: &PreparedTransaction) -> Result<SignedTransaction, PoolError> {
        pollster::block_on(self.inner.sign(prepared))
    }

    pub fn spendable_notes(&self) -> Result<Vec<SpendableNote>, PoolError> {
        pollster::block_on(self.inner.spendable_notes())
    }

    pub fn notes(&self) -> Result<Vec<UserNoteSummary>, PoolError> {
        pollster::block_on(self.inner.notes())
    }

    pub fn balance(&self) -> Result<NoteAmount, PoolError> {
        pollster::block_on(self.inner.balance())
    }

    pub fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        pollster::block_on(self.inner.simulate(prepared))
    }

    pub fn submit(&self, signed_tx: SignedTransaction) -> Result<String, PoolError> {
        pollster::block_on(self.inner.submit(signed_tx))
    }

    pub fn confirm(&self, hash: &str) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.inner.confirm(hash))
    }

    pub fn disclose(
        &self,
        req: crate::DisclosureRequest,
    ) -> Result<Option<types::DisclosureReceipt>, PoolError> {
        pollster::block_on(self.inner.disclose(req))
    }

    pub fn verify_disclosure(
        &self,
        receipt: &types::DisclosureReceipt,
        expected_vk_hash: &str,
    ) -> Result<types::DisclosureVerificationReport, PoolError> {
        pollster::block_on(self.inner.verify_disclosure(receipt, expected_vk_hash))
    }
}
