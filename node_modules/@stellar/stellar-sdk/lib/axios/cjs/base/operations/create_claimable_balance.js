'use strict';

var curr_generated = require('../generated/curr_generated.js');
var asset = require('../asset.js');
var operations = require('../util/operations.js');

function createClaimableBalance(opts) {
  if (!(opts.asset instanceof asset.Asset)) {
    throw new Error(
      "must provide an asset for create claimable balance operation"
    );
  }
  if (!operations.isValidAmount(opts.amount)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  if (!Array.isArray(opts.claimants) || opts.claimants.length === 0) {
    throw new Error("must provide at least one claimant");
  }
  const asset$1 = opts.asset.toXDRObject();
  const amount = operations.toXDRAmount(opts.amount);
  const claimants = opts.claimants.map((c) => c.toXDRObject());
  const createClaimableBalanceOp = new curr_generated.default.CreateClaimableBalanceOp({
    asset: asset$1,
    amount,
    claimants
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.createClaimableBalance(createClaimableBalanceOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.createClaimableBalance = createClaimableBalance;
//# sourceMappingURL=create_claimable_balance.js.map
