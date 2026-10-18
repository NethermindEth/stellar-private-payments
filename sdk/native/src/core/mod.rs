//! Shared pool config, planning, and helpers (all targets).

use crate::{
    planner::{SpendSession, SpendTarget, SpendableNote, Transact},
    transact::deposit_ext_amount,
    types::{EncryptionPublicKey, Estimate, NoteAmount, NotePublicKey, PrivatePoolConfig},
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
        fee: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        if amount.is_zero() {
            return Err(Error::InvalidConfig("amount must be > 0".into()));
        }
        let session = SpendSession::setup(
            wallet.to_vec(),
            amount,
            fee,
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
        fee: NoteAmount,
    ) -> Result<PreparedTransactionPlan, Error> {
        if amount.is_zero() {
            return Err(Error::InvalidConfig("amount must be > 0".into()));
        }
        let recipient = recipient.into();
        self.check_withdrawal_recipient(&recipient)?;
        let session = SpendSession::setup(
            wallet.to_vec(),
            amount,
            fee,
            self.config.pool_contract_id.clone(),
            SpendTarget::withdraw(recipient),
        )?;
        Ok(PreparedTransactionPlan::from_session(session)?)
    }

    /// Refuses a withdrawal to a contract of this deployment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WithdrawalToContract`] for such a `recipient`.
    pub fn check_withdrawal_recipient(&self, recipient: &str) -> Result<(), Error> {
        if self
            .config
            .contract_config
            .is_deployment_contract(recipient)
        {
            return Err(Error::WithdrawalToContract);
        }
        Ok(())
    }

    pub fn estimate(
        &self,
        wallet: &[SpendableNote],
        amount: NoteAmount,
        fee: NoteAmount,
    ) -> Result<Estimate, Error> {
        let plan = crate::planner::plan(amount, fee, wallet)?;
        Ok(Estimate {
            tx_count: u32::try_from(plan.len()).unwrap_or(u32::MAX),
            fees: crate::planner::fees(plan.len(), fee)?,
        })
    }

    pub fn deposit_transact_step(
        &self,
        note_pub: NotePublicKey,
        enc_pub: EncryptionPublicKey,
        amount: NoteAmount,
        fee: NoteAmount,
    ) -> Result<Transact, Error> {
        let ext_amount = deposit_ext_amount(amount, fee).ok_or_else(|| {
            Error::Other(anyhow::anyhow!(
                "deposit amount plus fee exceeds ext_amount range"
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
    use crate::{
        planner::{PlanError, SpendSessionError},
        types::{
            AssetDescriptor, ContractConfig, ExtAmount, GvkMode, NoteOwnerAddress, PoolConfigEntry,
            SignerAddress,
        },
    };

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
                NoteAmount::ZERO,
            )
        };

        let at_max = step(i128::MAX.unsigned_abs()).expect("i128::MAX converts");
        assert_eq!(at_max.ext_amount, ExtAmount::MAX);
        assert!(matches!(step(1 << 127), Err(Error::Other(_))));
    }

    // Every id but the pool's and its token's is empty.
    fn core() -> PoolCore {
        PoolCore {
            config: PrivatePoolConfig {
                contract_config: ContractConfig {
                    pools: vec![PoolConfigEntry {
                        pool_contract_id: "POOL".into(),
                        token_contract_id: "TOKEN".into(),
                        deployment_ledger: 0,
                        enabled: true,
                        asset: AssetDescriptor::Native,
                        policy_flags: Default::default(),
                        gvk_mode: GvkMode::Off,
                        gvk_authority_pub_key: None,
                    }],
                    ..ContractConfig::default()
                },
                pool_contract_id: "POOL".into(),
                user_address: NoteOwnerAddress::new("OWNER"),
                signer_address: SignerAddress::new("SIGNER"),
            },
        }
    }

    #[test]
    fn a_deposit_sends_the_amount_plus_the_fee() {
        let step = core()
            .deposit_transact_step(
                NotePublicKey([1; 32]),
                EncryptionPublicKey([2; 32]),
                NoteAmount::from(10),
                NoteAmount::from(3),
            )
            .expect("deposit step");

        assert_eq!(step.ext_amount, ExtAmount::from(13));
        assert_eq!(
            step.output_amounts,
            [NoteAmount::from(10), NoteAmount::ZERO]
        );
    }

    #[test]
    fn a_withdrawal_to_a_deployment_contract_is_refused_before_planning() {
        let core = core();
        let withdraw = |recipient: &str| {
            core.prepare_withdraw(&[], NoteAmount::from(10), recipient, NoteAmount::from(3))
        };

        let result = withdraw("POOL");
        assert!(
            matches!(result, Err(Error::WithdrawalToContract)),
            "{result:?}"
        );
        let result = withdraw("");
        assert!(
            matches!(
                result,
                Err(Error::SpendSession(
                    SpendSessionError::MissingWithdrawRecipient
                ))
            ),
            "{result:?}"
        );
        let result = withdraw("GRECIPIENT");
        assert!(
            matches!(
                result,
                Err(Error::SpendSession(SpendSessionError::Plan(
                    PlanError::NoSpendableNotes
                )))
            ),
            "{result:?}"
        );
    }
}
