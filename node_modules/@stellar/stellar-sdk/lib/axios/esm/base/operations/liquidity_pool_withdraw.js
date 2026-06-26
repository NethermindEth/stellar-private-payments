import { Buffer } from 'buffer';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function liquidityPoolWithdraw(opts = {}) {
  if (!opts.liquidityPoolId) {
    throw new TypeError("liquidityPoolId argument is required");
  }
  const liquidityPoolId = Buffer.from(
    opts.liquidityPoolId,
    "hex"
  );
  if (!isValidAmount(opts.amount)) {
    throw new TypeError(constructAmountRequirementsError("amount"));
  }
  const amount = toXDRAmount(opts.amount);
  if (!isValidAmount(opts.minAmountA, true)) {
    throw new TypeError(constructAmountRequirementsError("minAmountA"));
  }
  const minAmountA = toXDRAmount(opts.minAmountA);
  if (!isValidAmount(opts.minAmountB, true)) {
    throw new TypeError(constructAmountRequirementsError("minAmountB"));
  }
  const minAmountB = toXDRAmount(opts.minAmountB);
  const liquidityPoolWithdrawOp = new types.LiquidityPoolWithdrawOp({
    liquidityPoolId,
    amount,
    minAmountA,
    minAmountB
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.liquidityPoolWithdraw(liquidityPoolWithdrawOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { liquidityPoolWithdraw };
//# sourceMappingURL=liquidity_pool_withdraw.js.map
