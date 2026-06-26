import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';
import { validateClaimableBalanceId } from './claim_claimable_balance.js';

function clawbackClaimableBalance(opts = {}) {
  validateClaimableBalanceId(opts.balanceId);
  const balanceId = types.ClaimableBalanceId.fromXDR(
    opts.balanceId,
    "hex"
  );
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.clawbackClaimableBalance(
      new types.ClawbackClaimableBalanceOp({ balanceId })
    )
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { clawbackClaimableBalance };
//# sourceMappingURL=clawback_claimable_balance.js.map
