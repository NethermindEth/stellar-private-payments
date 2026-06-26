'use strict';

var curr_generated = require('./generated/curr_generated.js');
var asset = require('./asset.js');
var hashing = require('./hashing.js');

const LiquidityPoolFeeV18 = 30;
function getLiquidityPoolId(liquidityPoolType, liquidityPoolParameters) {
  if (liquidityPoolType !== "constant_product") {
    throw new Error("liquidityPoolType is invalid");
  }
  const { assetA, assetB, fee } = liquidityPoolParameters ?? {};
  if (!assetA || !(assetA instanceof asset.Asset)) {
    throw new Error("assetA is invalid");
  }
  if (!assetB || !(assetB instanceof asset.Asset)) {
    throw new Error("assetB is invalid");
  }
  if (!fee || fee !== LiquidityPoolFeeV18) {
    throw new Error("fee is invalid");
  }
  if (asset.Asset.compare(assetA, assetB) !== -1) {
    throw new Error("Assets are not in lexicographic order");
  }
  const payload = curr_generated.default.LiquidityPoolParameters.liquidityPoolConstantProduct(
    new curr_generated.default.LiquidityPoolConstantProductParameters({
      assetA: assetA.toXDRObject(),
      assetB: assetB.toXDRObject(),
      fee
    })
  ).toXDR();
  return hashing.hash(payload);
}

exports.LiquidityPoolFeeV18 = LiquidityPoolFeeV18;
exports.getLiquidityPoolId = getLiquidityPoolId;
//# sourceMappingURL=get_liquidity_pool_id.js.map
