use crate::plan::PlanError;

#[derive(Debug, thiserror::Error)]
pub enum SpendSessionError {
    #[error(transparent)]
    Plan(#[from] PlanError),

    #[error("spend session is already complete")]
    Complete,

    #[error("withdraw amount does not fit in ext_amount")]
    ExtAmountOverflow,

    #[error("withdraw requires a recipient address")]
    MissingWithdrawRecipient,
}
