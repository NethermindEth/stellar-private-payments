'use strict';

var buffer = require('buffer');
var operations = require('../util/operations.js');
var curr_generated = require('../generated/curr_generated.js');

function liquidityPoolDeposit(opts = {}) {
  const { liquidityPoolId, maxAmountA, maxAmountB, minPrice, maxPrice } = opts;
  if (!liquidityPoolId) {
    throw new TypeError("liquidityPoolId argument is required");
  }
  const liquidityPoolIdXdr = buffer.Buffer.from(
    liquidityPoolId,
    "hex"
  );
  if (!operations.isValidAmount(maxAmountA, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("maxAmountA"));
  }
  const maxAmountAXdr = operations.toXDRAmount(maxAmountA);
  if (!operations.isValidAmount(maxAmountB, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("maxAmountB"));
  }
  const maxAmountBXdr = operations.toXDRAmount(maxAmountB);
  if (minPrice === void 0) {
    throw new TypeError("minPrice argument is required");
  }
  const minPriceXdr = operations.toXDRPrice(minPrice);
  if (maxPrice === void 0) {
    throw new TypeError("maxPrice argument is required");
  }
  const maxPriceXdr = operations.toXDRPrice(maxPrice);
  const liquidityPoolDepositOp = new curr_generated.default.LiquidityPoolDepositOp({
    liquidityPoolId: liquidityPoolIdXdr,
    maxAmountA: maxAmountAXdr,
    maxAmountB: maxAmountBXdr,
    minPrice: minPriceXdr,
    maxPrice: maxPriceXdr
  });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.liquidityPoolDeposit(liquidityPoolDepositOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.liquidityPoolDeposit = liquidityPoolDeposit;
//# sourceMappingURL=liquidity_pool_deposit.js.map
