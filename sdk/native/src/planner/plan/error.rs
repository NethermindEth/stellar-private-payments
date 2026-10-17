/// The reason the planner cannot plan a spend or resolve its notes.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// The wallet holds no note it can spend.
    #[error("no spendable notes")]
    NoSpendableNotes,

    /// No set of notes pays the amount and a pool fee per transaction.
    #[error("you can send at most {max_spend} base units after pool fees")]
    NoCombination {
        /// The most the spendable notes can send after a pool fee per
        /// transaction, an amount a plan reaches exactly.
        max_spend: crate::types::NoteAmount,
    },

    /// A plan names a note past the end of the wallet.
    #[error("note index {index} is out of range for the wallet")]
    NoteIndexOutOfRange { index: usize },

    /// A sum of note amounts overflows
    /// [`NoteAmount`](crate::types::NoteAmount).
    #[error("input amount overflow")]
    InputAmountOverflow,

    /// A planner invariant failed.
    #[error("planner internal error: {reason}")]
    InternalError { reason: &'static str },

    /// The planner built steps that do not form a valid plan.
    #[error("planner produced an invalid transaction plan")]
    InvalidPlan,

    /// A step names a commitment no spendable note has.
    #[error("no spendable note with commitment {commitment}")]
    CommitmentNotFound { commitment: crate::types::Field },

    /// A step names a note by commitment with an amount the note lacks.
    #[error("note {commitment} has amount {actual}, expected {expected}")]
    NoteAmountMismatch {
        commitment: crate::types::Field,
        actual: crate::types::NoteAmount,
        expected: crate::types::NoteAmount,
    },

    /// A step names an amount no spendable note has.
    #[error("no spendable note with amount {amount}")]
    NoNoteForAmount { amount: crate::types::NoteAmount },

    /// A step names an amount more than one spendable note has.
    #[error("multiple spendable notes with amount {amount}")]
    AmbiguousNoteForAmount { amount: crate::types::NoteAmount },
}

impl PlanError {
    pub(crate) const fn internal(reason: &'static str) -> Self {
        Self::InternalError { reason }
    }
}
