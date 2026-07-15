//! Shared pool config, planning, and helpers (all targets).

use tx_planner::{SpendSession, SpendTarget, SpendableNote, Transact};
use types::{EncryptionPublicKey, ExtAmount, NoteAmount, NotePublicKey};

use crate::{
    error::Error,
    plan::PreparedTransactionPlan,
    types::{Estimate, PrivatePoolConfig},
};

mod plan;
mod state;

pub(crate) use plan::{pool_transact_input, transact_step_for_plan};
pub(crate) use state::process_local_state;
pub use state::process_local_state_batch;

/// Config and planning for one privacy pool.
pub struct PoolCore {
    config: PrivatePoolConfig,
}

impl PoolCore {
    pub fn new(config: PrivatePoolConfig) -> Result<Self, Error> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &PrivatePoolConfig {
        &self.config
    }

    pub fn prepare_deposit(&self, amount: NoteAmount) -> Result<PreparedTransactionPlan, Error> {
        if amount.is_zero() {
            return Err(Error::InvalidConfig("amount must be > 0".into()));
        }
        Ok(PreparedTransactionPlan::deposit(amount))
    }

    pub fn prepare_transfer(
        &self,
        wallet: &[SpendableNote],
        note_public_key: NotePublicKey,
        encryption_public_key: EncryptionPublicKey,
        amount: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        if amount.is_zero() {
            return Err(Error::InvalidConfig("amount must be > 0".into()));
        }
        let session = SpendSession::setup(
            wallet.to_vec(),
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::transfer(note_public_key, encryption_public_key),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(Error::from)
    }

    pub fn prepare_withdraw(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        recipient: impl Into<String>,
    ) -> Result<PreparedTransactionPlan, Error> {
        if amount.is_zero() {
            return Err(Error::InvalidConfig("amount must be > 0".into()));
        }
        let session = SpendSession::setup(
            wallet.to_vec(),
            amount,
            self.config.pool_contract_id.clone(),
            SpendTarget::withdraw(recipient.into()),
        )?;
        PreparedTransactionPlan::from_session(session).map_err(Error::from)
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, Error> {
        let plan = tx_planner::plan(amount, wallet)?;
        Ok(Estimate {
            tx_count: u32::try_from(plan.len()).unwrap_or(u32::MAX),
        })
    }

    pub fn deposit_transact_step(
        &self,
        note_pub: types::NotePublicKey,
        enc_pub: types::EncryptionPublicKey,
        amount: NoteAmount,
    ) -> Result<Transact, Error> {
        let ext_amount = ExtAmount::try_from(amount)
            .map_err(|_| Error::Other("deposit amount exceeds ext_amount range".into()))?;

        Ok(Transact::new(
            Vec::new(),
            [amount, NoteAmount::ZERO],
            ext_amount,
            self.config.pool_contract_id.clone(),
            [Some(note_pub.clone()), Some(note_pub)],
            [Some(enc_pub.clone()), Some(enc_pub)],
        ))
    }
}
