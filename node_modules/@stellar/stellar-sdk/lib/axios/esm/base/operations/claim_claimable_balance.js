import { setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function claimClaimableBalance(opts = {}) {
  validateClaimableBalanceId(opts.balanceId);
  const balanceId = types.ClaimableBalanceId.fromXDR(
    opts.balanceId,
    "hex"
  );
  const claimClaimableBalanceOp = new types.ClaimClaimableBalanceOp({
    balanceId
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.claimClaimableBalance(claimClaimableBalanceOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}
function validateClaimableBalanceId(balanceId) {
  if (typeof balanceId !== "string" || balanceId.length !== 8 + 64) {
    throw new Error("must provide a valid claimable balance id");
  }
}

export { claimClaimableBalance, validateClaimableBalanceId };
//# sourceMappingURL=claim_claimable_balance.js.map
