//! Sync wrapper around [`crate::PrivatePool`] via pollster.

use state::Storage;
use tx_planner::SpendableNote;
use types::NoteAmount;

use crate::{
    PoolCore, PreparedTransaction,
    error::PoolError,
    plan::PreparedTransactionPlan,
    pool::PrivatePool as AsyncPrivatePool,
    pool_storage::NativePoolBackend,
    prover::LocalProver,
    signer::TransactionSigner,
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactionResult,
        TransferRecipient,
    },
};

use super::Indexer;

/// Native sync wallet — [`AsyncPrivatePool`] with blocking method names.
pub struct PrivatePool(AsyncPrivatePool<NativePoolBackend>);

impl PrivatePool {
    pub fn open(
        config: PrivatePoolConfig,
        signer: Box<dyn TransactionSigner>,
    ) -> Result<Self, PoolError> {
        let backend = NativePoolBackend::open(
            &config.rpc_url,
            &config.storage_path,
            &config.contract_config,
        )?;
        let prover = Box::new(LocalProver::from_artifacts(&config.prover_artifacts)?);
        Ok(Self(AsyncPrivatePool::init(
            config, backend, signer, prover,
        )?))
    }

    pub fn into_inner(self) -> AsyncPrivatePool<NativePoolBackend> {
        self.0
    }

    pub fn inner(&self) -> &AsyncPrivatePool<NativePoolBackend> {
        &self.0
    }

    pub fn inner_mut(&mut self) -> &mut AsyncPrivatePool<NativePoolBackend> {
        &mut self.0
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        self.0.config()
    }

    pub fn core(&self) -> &PoolCore {
        self.0.core()
    }

    pub fn chain_config(&self) -> &crate::types::PoolChainConfig {
        self.0.core().config()
    }

    pub fn signer(&self) -> &dyn TransactionSigner {
        self.0.signer()
    }

    pub fn storage(&self) -> std::cell::Ref<'_, Storage> {
        self.0
            .pool_storage()
            .expect("native pool storage is always initialized")
            .storage()
    }

    pub fn storage_mut(&self) -> std::cell::RefMut<'_, Storage> {
        self.0
            .pool_storage()
            .expect("native pool storage is always initialized")
            .storage_mut()
    }

    pub fn indexer_mut(&self) -> std::cell::RefMut<'_, Indexer> {
        self.0
            .pool_storage()
            .expect("native pool storage is always initialized")
            .indexer_mut()
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, PoolError> {
        self.0.estimate(wallet, amount)
    }

    pub fn deposit(&self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.0.deposit(amount))
    }

    pub fn transfer(
        &self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.0.transfer(wallet, recipient, amount))
    }

    pub fn withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.0.withdraw(wallet, amount, recipient))
    }

    pub fn transact(&self, step: tx_planner::Transact) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.0.transact(step))
    }

    pub fn sync(&self) -> Result<SyncResult, PoolError> {
        pollster::block_on(self.0.sync())
    }

    pub fn wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        pollster::block_on(self.0.wallet())
    }

    pub fn balance(&self) -> Result<NoteAmount, PoolError> {
        pollster::block_on(self.0.balance())
    }

    pub fn next_prepared_transaction(
        &self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        pollster::block_on(self.0.next_prepared_transaction(plan))
    }

    pub fn simulate(&self, prepared: &mut PreparedTransaction) -> Result<(), PoolError> {
        pollster::block_on(self.0.simulate(prepared))
    }

    pub fn submit(&self, signed_tx: SignedTransaction) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.0.submit(signed_tx))
    }
}
