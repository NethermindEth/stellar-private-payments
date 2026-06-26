'use strict';

var curr_generated = require('../generated/curr_generated.js');
var asset = require('../asset.js');
var liquidity_pool_asset = require('../liquidity_pool_asset.js');
var operations = require('../util/operations.js');

const MAX_INT64 = "9223372036854775807";
function changeTrust(opts) {
  const asset$1 = opts.asset ?? opts.line;
  let line;
  if (asset$1 instanceof asset.Asset) {
    line = asset$1.toChangeTrustXDRObject();
  } else if (asset$1 instanceof liquidity_pool_asset.LiquidityPoolAsset) {
    line = asset$1.toXDRObject();
  } else {
    throw new TypeError("asset must be Asset or LiquidityPoolAsset");
  }
  if (opts.limit !== void 0 && !operations.isValidAmount(opts.limit, true)) {
    throw new TypeError(operations.constructAmountRequirementsError("limit"));
  }
  const limit = opts.limit ? operations.toXDRAmount(opts.limit) : curr_generated.default.Int64.fromString(MAX_INT64);
  const changeTrustOp = new curr_generated.default.ChangeTrustOp({ line, limit });
  const opAttributes = {
    sourceAccount: null,
    body: curr_generated.default.OperationBody.changeTrust(changeTrustOp)
  };
  operations.setSourceAccount(opAttributes, opts);
  return new curr_generated.default.Operation(opAttributes);
}

exports.changeTrust = changeTrust;
//# sourceMappingURL=change_trust.js.map
