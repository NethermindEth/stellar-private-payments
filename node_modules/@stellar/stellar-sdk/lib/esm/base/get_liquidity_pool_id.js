import types from './generated/curr_generated.js';
import { Asset } from './asset.js';
import { hash } from './hashing.js';

const LiquidityPoolFeeV18 = 30;
function getLiquidityPoolId(liquidityPoolType, liquidityPoolParameters) {
  if (liquidityPoolType !== "constant_product") {
    throw new Error("liquidityPoolType is invalid");
  }
  const { assetA, assetB, fee } = liquidityPoolParameters ?? {};
  if (!assetA || !(assetA instanceof Asset)) {
    throw new Error("assetA is invalid");
  }
  if (!assetB || !(assetB instanceof Asset)) {
    throw new Error("assetB is invalid");
  }
  if (!fee || fee !== LiquidityPoolFeeV18) {
    throw new Error("fee is invalid");
  }
  if (Asset.compare(assetA, assetB) !== -1) {
    throw new Error("Assets are not in lexicographic order");
  }
  const payload = types.LiquidityPoolParameters.liquidityPoolConstantProduct(
    new types.LiquidityPoolConstantProductParameters({
      assetA: assetA.toXDRObject(),
      assetB: assetB.toXDRObject(),
      fee
    })
  ).toXDR();
  return hash(payload);
}

export { LiquidityPoolFeeV18, getLiquidityPoolId };
//# sourceMappingURL=get_liquidity_pool_id.js.map
