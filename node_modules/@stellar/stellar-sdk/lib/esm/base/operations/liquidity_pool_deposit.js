import { Buffer } from 'buffer';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, toXDRPrice, setSourceAccount } from '../util/operations.js';
import types from '../generated/curr_generated.js';

function liquidityPoolDeposit(opts = {}) {
  const { liquidityPoolId, maxAmountA, maxAmountB, minPrice, maxPrice } = opts;
  if (!liquidityPoolId) {
    throw new TypeError("liquidityPoolId argument is required");
  }
  const liquidityPoolIdXdr = Buffer.from(
    liquidityPoolId,
    "hex"
  );
  if (!isValidAmount(maxAmountA, true)) {
    throw new TypeError(constructAmountRequirementsError("maxAmountA"));
  }
  const maxAmountAXdr = toXDRAmount(maxAmountA);
  if (!isValidAmount(maxAmountB, true)) {
    throw new TypeError(constructAmountRequirementsError("maxAmountB"));
  }
  const maxAmountBXdr = toXDRAmount(maxAmountB);
  if (minPrice === void 0) {
    throw new TypeError("minPrice argument is required");
  }
  const minPriceXdr = toXDRPrice(minPrice);
  if (maxPrice === void 0) {
    throw new TypeError("maxPrice argument is required");
  }
  const maxPriceXdr = toXDRPrice(maxPrice);
  const liquidityPoolDepositOp = new types.LiquidityPoolDepositOp({
    liquidityPoolId: liquidityPoolIdXdr,
    maxAmountA: maxAmountAXdr,
    maxAmountB: maxAmountBXdr,
    minPrice: minPriceXdr,
    maxPrice: maxPriceXdr
  });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.liquidityPoolDeposit(liquidityPoolDepositOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { liquidityPoolDeposit };
//# sourceMappingURL=liquidity_pool_deposit.js.map
