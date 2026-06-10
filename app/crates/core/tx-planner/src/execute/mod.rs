//! [`SpendSession`] — step through a [`TransactionPlan`] with wallet updates.

mod error;

pub use error::SpendSessionError;

use types::{EncryptionPublicKey, ExtAmount, Field, NoteAmount, NotePublicKey};

use crate::plan::{PlannedStep, SpendableNote, StepAction, plan};

/// Recipient data for the final step.
#[derive(Clone, Debug)]
pub enum SpendTarget {
    Transfer {
        recipient_note: NotePublicKey,
        recipient_enc: EncryptionPublicKey,
    },
    Withdraw {
        recipient: String,
    },
}

impl SpendTarget {
    pub fn transfer(recipient_note: NotePublicKey, recipient_enc: EncryptionPublicKey) -> Self {
        Self::Transfer {
            recipient_note,
            recipient_enc,
        }
    }

    pub fn withdraw(recipient: String) -> Self {
        Self::Withdraw { recipient }
    }
}

/// One on-chain `transact` call derived from the current plan step.
#[derive(Clone, Debug)]
pub struct Transact {
    pub input_commitments: Vec<Field>,
    pub output_amounts: [NoteAmount; 2],
    pub ext_amount: ExtAmount,
    pub ext_recipient: String,
    pub out_recipient_note_pubkeys: [Option<NotePublicKey>; 2],
    pub out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; 2],
}

impl Transact {
    pub fn new(
        input_commitments: Vec<Field>,
        output_amounts: [NoteAmount; 2],
        ext_amount: ExtAmount,
        ext_recipient: String,
        out_recipient_note_pubkeys: [Option<NotePublicKey>; 2],
        out_recipient_encryption_pubkeys: [Option<EncryptionPublicKey>; 2],
    ) -> Self {
        Self {
            input_commitments,
            output_amounts,
            ext_amount,
            ext_recipient,
            out_recipient_note_pubkeys,
            out_recipient_encryption_pubkeys,
        }
    }
}

/// Runs a frozen transaction plan step-by-step.
#[derive(Clone, Debug)]
pub struct SpendSession {
    steps: Vec<PlannedStep>,
    wallet: Vec<SpendableNote>,
    pool_address: String,
    target: SpendTarget,
    step_index: usize,
}

impl SpendSession {
    pub fn setup(
        wallet: Vec<SpendableNote>,
        amount: NoteAmount,
        pool_address: String,
        target: SpendTarget,
    ) -> Result<Self, SpendSessionError> {
        validate_target(&target)?;
        let tx_plan = plan(amount, &wallet)?;
        Ok(Self {
            steps: tx_plan.into_iter().collect(),
            wallet,
            pool_address,
            target,
            step_index: 0,
        })
    }

    pub fn is_done(&self) -> bool {
        self.step_index >= self.steps.len()
    }

    pub fn step_index(&self) -> usize {
        self.step_index
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    pub fn is_consolidate_step(&self) -> bool {
        self.steps
            .get(self.step_index)
            .is_some_and(|s| matches!(s.action, StepAction::Consolidate { .. }))
    }

    pub fn step(&self) -> Result<Option<Transact>, SpendSessionError> {
        if self.is_done() {
            return Ok(None);
        }

        let step = &self.steps[self.step_index];
        let resolved = step.resolve(&self.wallet)?;
        Ok(Some(materialize_step(
            step,
            &self.pool_address,
            &self.target,
            &resolved,
        )?))
    }

    /// Advance after a successful submit (`output_commitments` from prove
    /// result).
    pub fn complete_step(
        &mut self,
        output_commitments: &[Field; 2],
    ) -> Result<(), SpendSessionError> {
        if self.is_done() {
            return Err(SpendSessionError::Complete);
        }

        let step = self.steps[self.step_index].clone();
        let spent = step.resolve(&self.wallet)?;

        let merge_output = match step.action {
            StepAction::Consolidate { output } => Some(SpendableNote {
                commitment: output_commitments[0],
                amount: output,
            }),
            StepAction::Final { .. } => None,
        };

        match step.action {
            StepAction::Consolidate { .. } => {
                remove_spent(&mut self.wallet, &spent);
                self.wallet.push(merge_output.expect("consolidate merge"));
            }
            StepAction::Final { .. } => {
                remove_spent(&mut self.wallet, &spent);
            }
        }

        self.step_index = self
            .step_index
            .checked_add(1)
            .expect("step_index stays within plan length");
        Ok(())
    }
}

fn validate_target(target: &SpendTarget) -> Result<(), SpendSessionError> {
    if let SpendTarget::Withdraw { recipient } = target
        && recipient.is_empty()
    {
        return Err(SpendSessionError::MissingWithdrawRecipient);
    }
    Ok(())
}

fn materialize_step(
    step: &PlannedStep,
    pool_address: &str,
    target: &SpendTarget,
    resolved_inputs: &[SpendableNote],
) -> Result<Transact, SpendSessionError> {
    let input_commitments = resolved_inputs.iter().map(|note| note.commitment).collect();

    match step.action {
        StepAction::Consolidate { output } => Ok(Transact {
            input_commitments,
            output_amounts: [output, NoteAmount::ZERO],
            ext_amount: ExtAmount::ZERO,
            ext_recipient: pool_address.to_string(),
            out_recipient_note_pubkeys: [None, None],
            out_recipient_encryption_pubkeys: [None, None],
        }),
        StepAction::Final { outputs } => match target {
            SpendTarget::Transfer {
                recipient_note,
                recipient_enc,
            } => {
                let out1 = outputs.1.unwrap_or(NoteAmount::ZERO);
                let (out_note_pks, out_enc_pks) = if outputs.1.is_some() {
                    (
                        [Some(recipient_note.clone()), None],
                        [Some(recipient_enc.clone()), None],
                    )
                } else {
                    (
                        [Some(recipient_note.clone()), Some(recipient_note.clone())],
                        [Some(recipient_enc.clone()), Some(recipient_enc.clone())],
                    )
                };
                Ok(Transact {
                    input_commitments,
                    output_amounts: [outputs.0, out1],
                    ext_amount: ExtAmount::ZERO,
                    ext_recipient: pool_address.to_string(),
                    out_recipient_note_pubkeys: out_note_pks,
                    out_recipient_encryption_pubkeys: out_enc_pks,
                })
            }
            SpendTarget::Withdraw { recipient } => {
                let ext_amount = ExtAmount::try_from(outputs.0)
                    .map_err(|_| SpendSessionError::ExtAmountOverflow)?
                    .checked_neg()
                    .ok_or(SpendSessionError::ExtAmountOverflow)?;
                Ok(Transact {
                    input_commitments,
                    output_amounts: [outputs.1.unwrap_or(NoteAmount::ZERO), NoteAmount::ZERO],
                    ext_amount,
                    ext_recipient: recipient.clone(),
                    out_recipient_note_pubkeys: [None, None],
                    out_recipient_encryption_pubkeys: [None, None],
                })
            }
        },
    }
}

fn remove_spent(wallet: &mut Vec<SpendableNote>, spent: &[SpendableNote]) {
    for note in spent {
        wallet.retain(|n| n.commitment != note.commitment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NOTE_SALT: AtomicUsize = AtomicUsize::new(0);

    fn note(amount: u128) -> SpendableNote {
        let salt = NOTE_SALT.fetch_add(1, Ordering::Relaxed);
        let commitment_value = amount
            .checked_add(1_000)
            .and_then(|base| base.checked_add(salt as u128))
            .expect("test note commitment value overflow");
        SpendableNote {
            commitment: Field::from(NoteAmount::from(commitment_value)),
            amount: NoteAmount::from(amount),
        }
    }

    fn transfer_target() -> SpendTarget {
        SpendTarget::transfer(
            NotePublicKey::parse(
                "0x0000000000000000000000000000000000000000000000000000000000000001",
            )
            .expect("test note key"),
            EncryptionPublicKey::parse(
                "0x0000000000000000000000000000000000000000000000000000000000000002",
            )
            .expect("test enc key"),
        )
    }

    #[test]
    fn transfer_single_note() {
        let exec = SpendSession::setup(
            vec![note(10)],
            NoteAmount::from(10),
            "POOL".into(),
            transfer_target(),
        )
        .expect("setup transfer");
        let step = exec.step().expect("step").expect("one step");
        assert_eq!(step.ext_amount, ExtAmount::ZERO);
        assert_eq!(
            step.output_amounts,
            [NoteAmount::from(10), NoteAmount::ZERO]
        );
        assert!(step.out_recipient_note_pubkeys[0].is_some());
        assert!(step.out_recipient_note_pubkeys[1].is_some());
    }

    #[test]
    fn transfer_with_change() {
        let exec = SpendSession::setup(
            vec![note(15)],
            NoteAmount::from(10),
            "POOL".into(),
            transfer_target(),
        )
        .expect("setup transfer");
        let step = exec.step().expect("step").expect("one step");
        assert_eq!(step.ext_amount, ExtAmount::ZERO);
        assert_eq!(
            step.output_amounts,
            [NoteAmount::from(10), NoteAmount::from(5)]
        );
        assert!(step.out_recipient_note_pubkeys[0].is_some());
        assert!(step.out_recipient_encryption_pubkeys[0].is_some());
        assert!(step.out_recipient_note_pubkeys[1].is_none());
        assert!(step.out_recipient_encryption_pubkeys[1].is_none());
    }

    #[test]
    fn withdraw_with_change() {
        let exec = SpendSession::setup(
            vec![note(15)],
            NoteAmount::from(10),
            "POOL".into(),
            SpendTarget::withdraw(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF".into(),
            ),
        )
        .expect("setup withdraw");
        let step = exec.step().expect("step").expect("one step");
        assert_eq!(step.ext_amount, ExtAmount::from(-10));
        assert_eq!(step.output_amounts, [NoteAmount::from(5), NoteAmount::ZERO]);
    }

    #[test]
    fn complete_all_steps() {
        let mut exec = SpendSession::setup(
            vec![note(2), note(3), note(5)],
            NoteAmount::from(10),
            "POOL".into(),
            transfer_target(),
        )
        .expect("setup multi-step transfer");

        let mut steps = 0u32;
        while let Some(step) = exec.step().expect("step") {
            steps = steps.checked_add(1).expect("step count fits in u32");
            assert_eq!(exec.is_consolidate_step(), steps == 1);
            let merge = if step.output_amounts[0] == NoteAmount::from(8) {
                Field::from(NoteAmount::from(900))
            } else {
                Field::from(NoteAmount::from(1000))
            };
            exec.complete_step(&[merge, Field::ZERO])
                .expect("complete step");
        }

        assert_eq!(steps, 2);
        assert!(exec.is_done());
    }
}
