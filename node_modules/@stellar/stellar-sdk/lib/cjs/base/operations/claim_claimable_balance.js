'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function claimClaimableBalance(opts = {}) {
  validateClaimableBalanceId(opts.balanceId);
  const balanceId = curr_generated.default.ClaimableBalanceId.fromXDR(
    opts.balanceId,
    "hex"
  );
  const claimClaimableBalanceOp = new curr_generated.default.ClaimClaimableBalanceOp({
    balanceId
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.claimClaimableBalance(claimClaimableBalanceOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}
function validateClaimableBalanceId(balanceId) {
  if (typeof balanceId !== "string" || balanceId.length !== 8 + 64) {
    throw new Error("must provide a valid claimable balance id");
  }
}

exports.claimClaimableBalance = claimClaimableBalance;
exports.validateClaimableBalanceId = validateClaimableBalanceId;
//# sourceMappingURL=claim_claimable_balance.js.map
