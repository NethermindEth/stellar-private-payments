//! Per-pool private payments API.

use state::Storage;
use tx_planner::{SpendSession, SpendTarget, SpendableNote};
use types::NoteAmount;

use crate::{
    error::PoolError,
    plan::PreparedTransactionPlan,
    types::{
        Estimate, PreparedTransaction, PrivatePoolConfig, SignedTransaction, SyncResult,
        TransactRequest, TransactionResult, TransferRecipient,
    },
};

/// Main entry point for a single privacy pool.
pub struct PrivatePool {
    config: PrivatePoolConfig,
    storage: Option<Storage>,
}

impl PrivatePool {
    pub fn new(config: PrivatePoolConfig) -> Result<Self, PoolError> {
        if config.pool_contract_id.is_empty() {
            return Err(PoolError::InvalidConfig(
                "pool_contract_id must not be empty".into(),
            ));
        }
        if config.user_address.is_empty() {
            return Err(PoolError::InvalidConfig(
                "user_address must not be empty".into(),
            ));
        }
        Ok(Self {
            config,
            storage: None,
        })
    }

    pub fn initialize(&mut self) -> Result<(), PoolError> {
        let storage_path = &self.config.storage_path;
        self.storage = Some(
            Storage::connect_file(storage_path)
                .map_err(|e| PoolError::Other(format!("open storage: {e}")))?,
        );
        Ok(())
    }

    /// Fetch on-chain events and refresh local pool state.
    pub fn sync(&mut self) -> Result<SyncResult, PoolError> {
        Err(PoolError::NotImplemented)
    }

    pub fn get_balance(&self) -> Result<NoteAmount, PoolError> {
        let notes = self.spendable_wallet()?;
        let balance = notes.iter().fold(NoteAmount::ZERO, |mut acc, note| {
            acc += note.amount;
            acc
        });
        Ok(balance)
    }

    pub fn prepare_deposit(
        &mut self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        Ok(PreparedTransactionPlan::deposit(amount))
    }

    pub fn prepare_transfer(
        &mut self,
        recipient: TransferRecipient,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        let wallet = self.spendable_wallet()?;
        let session = SpendSession::setup(
            wallet,
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::transfer(recipient.note_public_key, recipient.encryption_public_key),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(PoolError::from)
    }

    pub fn prepare_withdraw(
        &mut self,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, PoolError> {
        if amount.is_zero() {
            return Err(PoolError::InvalidConfig("amount must be > 0".into()));
        }
        let wallet = self.spendable_wallet()?;
        let session = SpendSession::setup(
            wallet,
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::withdraw(self.config.user_address.clone()),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(PoolError::from)
    }

    pub fn estimate(&self, amount: NoteAmount) -> Result<Estimate, PoolError> {
        let wallet = self.spendable_wallet()?;
        let plan = tx_planner::plan(amount, &wallet)?;
        Ok(Estimate {
            tx_count: u32::try_from(plan.len()).unwrap_or(u32::MAX),
        })
    }

    pub fn prepare_transact(
        &mut self,
        _req: TransactRequest,
    ) -> Result<PreparedTransaction, PoolError> {
        Err(PoolError::NotImplemented)
    }

    /// Prove and simulate the current plan tx, then advance the plan.
    pub fn next_prepared_transaction(
        &mut self,
        plan: &mut PreparedTransactionPlan,
    ) -> Result<PreparedTransaction, PoolError> {
        if plan.is_complete() {
            return Err(PoolError::Other("transaction plan is complete".into()));
        }

        let output_commitments = plan.stub_output_commitments()?;

        // TODO: build transact params, prove, and simulate against RPC.
        let prepared = PreparedTransaction {
            tx_xdr: "stub-unsigned-xdr".into(),
            auth_entries: vec![],
            latest_ledger: 1,
        };

        plan.finish_proved_tx(&output_commitments)?;

        Ok(prepared)
    }

    pub fn submit(
        &mut self,
        _signed_tx: SignedTransaction,
    ) -> Result<TransactionResult, PoolError> {
        // TODO: submit signed XDR to Soroban RPC.
        Ok(TransactionResult {
            tx_hash: "stub-tx-hash".into(),
        })
    }

    fn spendable_wallet(&self) -> Result<Vec<SpendableNote>, PoolError> {
        let storage = self.storage.as_ref().ok_or(PoolError::NotInitialized)?;
        let pool_contract_id = &self.config.pool_contract_id;
        let user_address = &self.config.user_address;
        let spendable_notes = storage
            .list_unspent_user_notes(pool_contract_id, user_address)
            .map_err(|e| PoolError::Other(e.to_string()))?
            .into_iter()
            .map(|n| SpendableNote {
                commitment: n.id,
                amount: n.amount,
            })
            .collect();
        Ok(spendable_notes)
    }
}
