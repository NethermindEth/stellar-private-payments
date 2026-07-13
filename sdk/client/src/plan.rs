//! Logical transaction plans (tx-planner session), resolved one on-chain tx at
//! a time.

use tx_planner::{SpendSession, Transact};
use types::{Field, NoteAmount};

use crate::error::PoolError;

#[derive(Debug)]
pub(crate) enum PlanKind {
    Deposit { amount: NoteAmount },
    Spend(SpendSession),
    Raw(Transact),
}

/// Frozen multi-tx spend; each on-chain step is executed via
/// [`crate::pool::PrivatePool::transfer`] / [`withdraw`] / [`deposit`].
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

    pub fn from_transact(step: Transact) -> Self {
        Self {
            tx_count: 1,
            current_tx: 0,
            kind: PlanKind::Raw(step),
        }
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
        self.current_tx = self
            .current_tx
            .checked_add(1)
            .expect("advance past tx_count");
    }

    pub(crate) fn deposit_amount(&self) -> Option<NoteAmount> {
        match &self.kind {
            PlanKind::Deposit { amount } => Some(*amount),
            PlanKind::Spend(_) | PlanKind::Raw(_) => None,
        }
    }

    pub(crate) fn current_spend_step(
        &self,
    ) -> Result<Option<Transact>, tx_planner::SpendSessionError> {
        match &self.kind {
            PlanKind::Deposit { .. } | PlanKind::Raw(_) => Ok(None),
            PlanKind::Spend(session) => session.step(),
        }
    }

    pub(crate) fn raw_transact_step(&self) -> Option<&Transact> {
        match &self.kind {
            PlanKind::Raw(step) => Some(step),
            _ => None,
        }
    }

    pub(crate) fn finish_proved_tx(
        &mut self,
        output_commitments: &[Field; 2],
    ) -> Result<(), PoolError> {
        match self.kind_mut() {
            PlanKind::Deposit { .. } | PlanKind::Raw(_) => self.advance(),
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
