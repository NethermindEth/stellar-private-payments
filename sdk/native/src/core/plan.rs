use crate::planner::Transact;

use crate::chain::PoolTransactInput;

use crate::{PreparedTransaction, error::Error, plan::PreparedTransactionPlan};

pub(crate) fn transact_step_for_plan(plan: &PreparedTransactionPlan) -> Result<Transact, Error> {
    if plan.deposit_amount().is_some() {
        return Err(Error::Other(anyhow::anyhow!(
            "deposit transact step requires PoolCore::deposit_transact_step"
        )));
    }

    plan.current_spend_step()?
        .ok_or_else(|| Error::Other(anyhow::anyhow!("plan tx missing")))
}

pub(crate) fn pool_transact_input(prepared: &PreparedTransaction) -> PoolTransactInput {
    PoolTransactInput {
        proof_uncompressed: prepared.proof_uncompressed.clone(),
        ext_data: prepared.ext_data.clone(),
        public: (&prepared.prepared).into(),
    }
}
