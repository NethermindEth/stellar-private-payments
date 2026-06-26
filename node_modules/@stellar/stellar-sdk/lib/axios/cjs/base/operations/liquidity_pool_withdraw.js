'use strict';

var buffer = require('buffer');
var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function liquidityPoolWithdraw(opts = {}) {
  if (!opts.liquidityPoolId) {
    throw new TypeError("liquidityPoolId argument is required");
  }
  const liquidityPoolId = buffer.Buffer.from(
    opts.liquidityPoolId,
    "hex"
  );
  if (!operations.isValidAmount(opts.amount)) {
    throw new TypeError(operations.constructAmountRequirementsError("amount"));
  }
  const amount = operations.toXDRAmount(opts.amount);
  if (!operations.isValidAmount(opts.minAmountA, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("minAmountA"));
  }
  const minAmountA = operations.toXDRAmount(opts.minAmountA);
  if (!operations.isValidAmount(opts.minAmountB, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("minAmountB"));
  }
  const minAmountB = operations.toXDRAmount(opts.minAmountB);
  const liquidityPoolWithdrawOp = new curr_generated.default.LiquidityPoolWithdrawOp({
    liquidityPoolId,
    amount,
    minAmountA,
    minAmountB
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.liquidityPoolWithdraw(liquidityPoolWithdrawOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.liquidityPoolWithdraw = liquidityPoolWithdraw;
//# sourceMappingURL=liquidity_pool_withdraw.js.map
