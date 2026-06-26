'use strict';

var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');
var claim_claimable_balance = require('./claim_claimable_balance.js');

function clawbackClaimableBalance(opts = {}) {
  claim_claimable_balance.validateClaimableBalanceId(opts.balanceId);
  const balanceId = curr_generated.default.ClaimableBalanceId.fromXDR(
    opts.balanceId,
    "hex"
  );
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.clawbackClaimableBalance(
      new curr_generated.default.ClawbackClaimableBalanceOp({ balanceId })
    )
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.clawbackClaimableBalance = clawbackClaimableBalance;
//# sourceMappingURL=clawback_claimable_balance.js.map
