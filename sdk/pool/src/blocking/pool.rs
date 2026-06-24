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
    signer::TransactionSigner,
    types::{
        Estimate, PrivatePoolConfig, SignedTransaction, SyncResult, TransactChainContext,
        TransactionResult, TransferRecipient,
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
        Ok(Self(AsyncPrivatePool::with_storage(
            config, backend, signer,
        )?))
    }

    pub fn with_prover(mut self) -> Result<Self, PoolError> {
        pollster::block_on(self.0.load_prover())?;
        Ok(self)
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

    pub fn core_mut(&mut self) -> &mut PoolCore {
        self.0.core_mut()
    }

    pub fn chain_config(&self) -> &crate::types::PoolChainConfig {
        self.0.core().config()
    }

    pub fn signer(&self) -> &dyn TransactionSigner {
        self.0.signer()
    }

    pub fn set_signer(&mut self, signer: Box<dyn TransactionSigner>) {
        self.0.set_signer(signer);
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

    pub fn chain_context(&self) -> Result<&TransactChainContext, PoolError> {
        self.0.chain_context()
    }

    pub fn set_chain_context(&mut self, chain: TransactChainContext) {
        self.0.set_chain_context(chain);
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, PoolError> {
        self.0.estimate(wallet, amount)
    }

    pub fn deposit(&mut self, amount: NoteAmount) -> Result<TransactionResult, PoolError> {
        pollster::block_on(self.0.deposit(amount))
    }

    pub fn transfer(
        &mut self,
        wallet: &[SpendableNote],
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.0.transfer(wallet, recipient, amount))
    }

    pub fn withdraw(
        &mut self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Vec<TransactionResult>, PoolError> {
        pollster::block_on(self.0.withdraw(wallet, amount))
    }

    pub fn sync(&mut self) -> Result<SyncResult, PoolError> {
        pollster::block_on(self.0.sync())
    }

    pub fn wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        pollster::block_on(self.0.wallet())
    }

    pub fn refresh_chain_context(&mut self) -> Result<(), PoolError> {
        pollster::block_on(self.0.refresh_chain_context())
    }

    pub fn next_prepared_transaction(
        &mut self,
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
