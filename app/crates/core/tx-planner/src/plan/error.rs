#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("no spendable notes")]
    NoSpendableNotes,

    #[error("no combination of notes reaches the goal amount")]
    NoCombination,

    #[error("coin selection picked {selected} notes, exceeding limit of {max_notes}")]
    TooManyNotes { selected: usize, max_notes: usize },

    #[error("note index {index} is out of range for the wallet")]
    NoteIndexOutOfRange { index: usize },

    #[error("input amount overflow")]
    InputAmountOverflow,

    #[error("planner internal error: {reason}")]
    InternalError { reason: &'static str },

    #[error("planner produced an invalid transaction plan")]
    InvalidPlan,

    #[error("no spendable note with commitment {commitment}")]
    CommitmentNotFound { commitment: types::Field },

    #[error("note {commitment} has amount {actual}, expected {expected}")]
    NoteAmountMismatch {
        commitment: types::Field,
        actual: types::NoteAmount,
        expected: types::NoteAmount,
    },

    #[error("no spendable note with amount {amount}")]
    NoNoteForAmount { amount: types::NoteAmount },

    #[error("multiple spendable notes with amount {amount}")]
    AmbiguousNoteForAmount { amount: types::NoteAmount },
}

impl PlanError {
    pub(crate) const fn internal(reason: &'static str) -> Self {
        Self::InternalError { reason }
    }
}
