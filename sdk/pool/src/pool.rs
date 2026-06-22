//! Per-pool private payments API.

use tx_planner::PlanError;
use types::NoteAmount;

use crate::{
    error::PoolError,
    types::{
        Estimate, PreparedTransaction, PrivatePoolConfig, SignedTransaction, SyncResult,
        TransactRequest, TransactionResult, TransferRecipient,
    },
};

/// Main entry point for a single privacy pool.
pub struct PrivatePool {
    config: PrivatePoolConfig,
}

impl PrivatePool {
    /// Fast, mostly local setup — config and path validation.
    pub fn new(config: PrivatePoolConfig) -> Result<Self, PoolError> {
        if config.pool_contract_id.is_empty() {
            return Err(PoolError::InvalidConfig(
                "pool_contract_id must not be empty".into(),
            ));
        }
        Ok(Self { config })
    }

    /// Slow init: WASM/prover, network, wallet registration, etc.
    pub fn initialize(&mut self) -> Result<(), PoolError> {
        let _ = &self.config;
        Err(PoolError::NotImplemented)
    }

    /// Fetch on-chain events and refresh local pool state.
    pub fn sync(&mut self) -> Result<SyncResult, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn get_balance(&self) -> Result<NoteAmount, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn prepare_deposit(
        &mut self,
        _amount: NoteAmount,
    ) -> Result<PreparedTransaction, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn prepare_transfer(
        &mut self,
        _recipient: TransferRecipient,
        _amount: NoteAmount,
    ) -> Result<PreparedTransaction, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn prepare_withdraw(
        &mut self,
        _amount: NoteAmount,
    ) -> Result<PreparedTransaction, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn estimate(&self, _amount: NoteAmount) -> Result<Estimate, PlanError> {
        Err(PlanError::NoSpendableNotes)
    }

    pub fn prepare_transact(
        &mut self,
        _req: TransactRequest,
    ) -> Result<PreparedTransaction, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn submit(
        &mut self,
        _signed_tx: SignedTransaction,
    ) -> Result<TransactionResult, PoolError> {
        Err(PoolError::NotImplemented)
    }
}
