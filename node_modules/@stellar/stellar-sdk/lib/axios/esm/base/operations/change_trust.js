import types from '../generated/curr_generated.js';
import { Asset } from '../asset.js';
import { LiquidityPoolAsset } from '../liquidity_pool_asset.js';
import { isValidAmount, constructAmountRequirementsError, toXDRAmount, setSourceAccount } from '../util/operations.js';

const MAX_INT64 = "9223372036854775807";
function changeTrust(opts) {
  const asset = opts.asset ?? opts.line;
  let line;
  if (asset instanceof Asset) {
    line = asset.toChangeTrustXDRObject();
  } else if (asset instanceof LiquidityPoolAsset) {
    line = asset.toXDRObject();
  } else {
    throw new TypeError("asset must be Asset or LiquidityPoolAsset");
  }
  if (opts.limit !== void 0 && !isValidAmount(opts.limit, true)) {
    throw new TypeError(constructAmountRequirementsError("limit"));
  }
  const limit = opts.limit ? toXDRAmount(opts.limit) : types.Int64.fromString(MAX_INT64);
  const changeTrustOp = new types.ChangeTrustOp({ line, limit });
  const opAttributes = {
    sourceAccount: null,
    body: types.OperationBody.changeTrust(changeTrustOp)
  };
  setSourceAccount(opAttributes, opts);
  return new types.Operation(opAttributes);
}

export { changeTrust };
//# sourceMappingURL=change_trust.js.map
