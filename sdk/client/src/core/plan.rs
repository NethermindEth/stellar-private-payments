use tx_planner::Transact;

use stellar::PoolTransactInput;

use crate::{PreparedTransaction, error::Error, plan::PreparedTransactionPlan};

pub(crate) fn transact_step_for_plan(plan: &PreparedTransactionPlan) -> Result<Transact, Error> {
    if plan.deposit_amount().is_some() {
        return Err(Error::Other(
            "deposit transact step requires PoolCore::deposit_transact_step".into(),
        ));
    }

    plan.current_spend_step()?
        .ok_or_else(|| Error::Other("plan tx missing".into()))
}

pub(crate) fn pool_transact_input(prepared: &PreparedTransaction) -> PoolTransactInput {
    PoolTransactInput {
        proof_uncompressed: prepared.proof_uncompressed.clone(),
        ext_data: prepared.ext_data.clone(),
        public: (&prepared.prepared).into(),
    }
}
