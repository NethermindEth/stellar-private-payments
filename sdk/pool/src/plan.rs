//! Logical transaction plans (tx-planner session), resolved one on-chain tx at
//! a time.

use tx_planner::SpendSession;
use types::{Field, NoteAmount};

use crate::error::PoolError;

#[derive(Debug)]
pub(crate) enum PlanKind {
    Deposit { amount: NoteAmount },
    Spend(SpendSession),
}

/// Frozen multi-tx spend; Soroban txs are produced lazily via
/// [`PrivatePool::next_prepared_transaction`].
#[derive(Debug)]
pub struct PreparedTransactionPlan {
    tx_count: u32,
    current_tx: u32,
    kind: PlanKind,
}

impl PreparedTransactionPlan {
    pub(crate) fn deposit(amount: NoteAmount) -> Self {
        Self {
            tx_count: 1,
            current_tx: 0,
            kind: PlanKind::Deposit { amount },
        }
    }

    pub(crate) fn from_session(
        session: SpendSession,
    ) -> Result<Self, tx_planner::SpendSessionError> {
        let tx_count =
            u32::try_from(session.len()).map_err(|_| tx_planner::SpendSessionError::Complete)?;
        Ok(Self {
            tx_count,
            current_tx: 0,
            kind: PlanKind::Spend(session),
        })
    }

    pub fn tx_count(&self) -> u32 {
        self.tx_count
    }

    pub fn current_tx(&self) -> u32 {
        self.current_tx
    }

    pub fn is_complete(&self) -> bool {
        self.current_tx >= self.tx_count
    }

    pub(crate) fn kind_mut(&mut self) -> &mut PlanKind {
        &mut self.kind
    }

    pub(crate) fn advance(&mut self) {
        self.current_tx += 1;
    }

    /// Stub prove result until real proving is wired.
    pub(crate) fn stub_output_commitments(&mut self) -> Result<[Field; 2], PoolError> {
        match self.kind_mut() {
            PlanKind::Deposit { .. } => Ok([Field::ZERO, Field::ZERO]),
            PlanKind::Spend(session) => {
                let step = session.step()?;
                let step = step.ok_or(PoolError::Other("plan tx missing".into()))?;
                let merge = if step.output_amounts[0] == NoteAmount::from(8) {
                    Field::from(NoteAmount::from(900))
                } else {
                    Field::from(NoteAmount::from(1000))
                };
                Ok([merge, Field::ZERO])
            }
        }
    }

    pub(crate) fn finish_proved_tx(
        &mut self,
        output_commitments: &[Field; 2],
    ) -> Result<(), PoolError> {
        match self.kind_mut() {
            PlanKind::Deposit { .. } => self.advance(),
            PlanKind::Spend(_) => self.complete_pending_spend(output_commitments)?,
        }
        Ok(())
    }

    pub(crate) fn complete_pending_spend(
        &mut self,
        output_commitments: &[Field; 2],
    ) -> Result<(), tx_planner::SpendSessionError> {
        if let PlanKind::Spend(session) = self.kind_mut() {
            session.complete_step(output_commitments)?;
        }
        self.advance();
        Ok(())
    }
}
