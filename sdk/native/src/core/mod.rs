//! Shared pool config, planning, and helpers (all targets).

use crate::{
    planner::{SpendSession, SpendTarget, SpendableNote, Transact},
    types::{
        EncryptionPublicKey, Estimate, ExtAmount, NoteAmount, NotePublicKey, PrivatePoolConfig,
    },
};

use crate::{error::Error, plan::PreparedTransactionPlan};

mod plan;

pub(crate) use crate::state::process_local_state;
pub(crate) use plan::{pool_transact_input, transact_step_for_plan};

/// Config and planning for one privacy pool.
pub(crate) struct PoolCore {
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
        Ok(PreparedTransactionPlan::from_session(session)?)
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
        Ok(PreparedTransactionPlan::from_session(session)?)
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
    ) -> Result<Estimate, Error> {
        let plan = crate::planner::plan(amount, wallet)?;
        Ok(Estimate {
            tx_count: u32::try_from(plan.len()).unwrap_or(u32::MAX),
        })
    }

    pub fn deposit_transact_step(
        &self,
        note_pub: NotePublicKey,
        enc_pub: EncryptionPublicKey,
        amount: NoteAmount,
    ) -> Result<Transact, Error> {
        let ext_amount = ExtAmount::try_from(amount).map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "deposit amount exceeds ext_amount range: {e}"
            ))
        })?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContractConfig, NoteOwnerAddress, SignerAddress};

    /// The deposit step converts its amount to an `ext_amount` before anything
    /// is proved, and `i128::MAX` is the largest amount that converts.
    #[test]
    fn deposit_above_i128_is_refused_before_proving() {
        let core = PoolCore {
            config: PrivatePoolConfig {
                contract_config: ContractConfig::default(),
                pool_contract_id: "CPOOL".into(),
                user_address: NoteOwnerAddress::new("GUSER"),
                signer_address: SignerAddress::new("GUSER"),
            },
        };
        let step = |amount: u128| {
            core.deposit_transact_step(
                NotePublicKey([1; 32]),
                EncryptionPublicKey([2; 32]),
                NoteAmount::from(amount),
            )
        };

        let at_max = step(i128::MAX.unsigned_abs()).expect("i128::MAX converts");
        assert_eq!(at_max.ext_amount, ExtAmount::MAX);
        assert!(matches!(step(1 << 127), Err(Error::Other(_))));
    }
}
