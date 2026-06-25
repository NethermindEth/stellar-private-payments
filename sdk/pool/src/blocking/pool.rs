//! Sync wrapper around [`crate::PrivatePool`] via pollster.

use state::SqliteStorage;
use tx_planner::SpendableNote;
use types::NoteAmount;

use crate::{
    PoolCore, PreparedTransaction,
    error::PoolError,
    pool::PrivatePool as AsyncPrivatePool,
    prover::LocalProver,
    signer::Signer,
    storage::LocalStorage,
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactionResult,
        TransferRecipient,
    },
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

    pub fn core(&self) -> &PoolCore {
        self.inner.core()
    }

    pub fn chain_config(&self) -> &crate::types::PoolChainConfig {
        self.inner.core().config()
    }

    pub fn storage(&self) -> std::cell::Ref<'_, SqliteStorage> {
        self.inner.storage_backend().storage()
    }

    pub fn storage_mut(&self) -> std::cell::RefMut<'_, SqliteStorage> {
        self.inner.storage_backend().storage_mut()
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, PoolError> {
        self.inner.estimate(wallet, amount)
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

    pub fn sync(&self) -> Result<SyncResult, PoolError> {
        pollster::block_on(self.inner.sync())
    }

    pub fn wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        pollster::block_on(self.inner.wallet())
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
}
