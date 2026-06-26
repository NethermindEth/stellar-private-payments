import types from './generated/curr_generated.js';
import { Asset } from './asset.js';
import { LiquidityPoolFeeV18, getLiquidityPoolId } from './get_liquidity_pool_id.js';

class LiquidityPoolAsset {
  assetA;
  assetB;
  fee;
  /**
   * @param assetA - The first asset in the Pool, it must respect the rule `assetA < assetB`. See {@link Asset.compare} for more details on how assets are sorted.
   * @param assetB - The second asset in the Pool, it must respect the rule `assetA < assetB`. See {@link Asset.compare} for more details on how assets are sorted.
   * @param fee - The liquidity pool fee. For now the only fee supported is `30`.
   */
  constructor(assetA, assetB, fee) {
    if (!assetA || !(assetA instanceof Asset)) {
      throw new Error("assetA is invalid");
    }
    if (!assetB || !(assetB instanceof Asset)) {
      throw new Error("assetB is invalid");
    }
    if (Asset.compare(assetA, assetB) !== -1) {
      throw new Error("Assets are not in lexicographic order");
    }
    if (!fee || fee !== LiquidityPoolFeeV18) {
      throw new Error("fee is invalid");
    }
    this.assetA = assetA;
    this.assetB = assetB;
    this.fee = fee;
  }
  /**
   * Returns a liquidity pool asset object from its XDR ChangeTrustAsset object
   * representation.
   *
   * @param ctAssetXdr - The asset XDR object.
   */
  static fromOperation(ctAssetXdr) {
    const assetType = ctAssetXdr.switch();
    if (assetType === types.AssetType.assetTypePoolShare()) {
      const liquidityPoolParameters = ctAssetXdr.liquidityPool().constantProduct();
      return new this(
        Asset.fromOperation(liquidityPoolParameters.assetA()),
        Asset.fromOperation(liquidityPoolParameters.assetB()),
        liquidityPoolParameters.fee()
      );
    }
    throw new Error(`Invalid asset type: ${assetType.name}`);
  }
  /**
   * Returns the `xdr.ChangeTrustAsset` object for this liquidity pool asset.
   *
   * Note: To convert from an {@link Asset | `Asset`} to `xdr.ChangeTrustAsset`
   * please refer to the
   * {@link Asset.toChangeTrustXDRObject | `Asset.toChangeTrustXDRObject`} method.
   */
  toXDRObject() {
    const lpConstantProductParamsXdr = new types.LiquidityPoolConstantProductParameters({
      assetA: this.assetA.toXDRObject(),
      assetB: this.assetB.toXDRObject(),
      fee: this.fee
    });
    const lpParamsXdr = types.LiquidityPoolParameters.liquidityPoolConstantProduct(
      lpConstantProductParamsXdr
    );
    return types.ChangeTrustAsset.assetTypePoolShare(lpParamsXdr);
  }
  /**
   * Returns liquidity pool parameters.
   */
  getLiquidityPoolParameters() {
    return {
      ...this,
      assetA: this.assetA,
      assetB: this.assetB,
      fee: this.fee
    };
  }
  /**
   * Returns the asset type, always `"liquidity_pool_shares"`.
   *
   * @see [Assets concept](https://developers.stellar.org/docs/glossary/assets/)
   */
  getAssetType() {
    return "liquidity_pool_shares";
  }
  /**
   * Returns true if this liquidity pool asset equals the given one.
   *
   * @param other - the LiquidityPoolAsset to compare
   */
  equals(other) {
    return this.assetA.equals(other.assetA) && this.assetB.equals(other.assetB) && this.fee === other.fee;
  }
  /** Returns a string representation in `liquidity_pool:<hex pool id>` format. */
  toString() {
    const poolId = getLiquidityPoolId(
      "constant_product",
      this.getLiquidityPoolParameters()
    ).toString("hex");
    return `liquidity_pool:${poolId}`;
  }
}

export { LiquidityPoolAsset };
//# sourceMappingURL=liquidity_pool_asset.js.map
