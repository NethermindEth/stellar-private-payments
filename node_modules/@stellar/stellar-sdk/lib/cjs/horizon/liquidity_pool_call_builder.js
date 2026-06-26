'use strict';

var call_builder = require('./call_builder.js');

class LiquidityPoolCallBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient);
    this.setPath("liquidity_pools");
  }
  /**
   * Filters out pools whose reserves don't exactly match these assets.
   *
   * @see Asset
   * @returns current LiquidityPoolCallBuilder instance
   */
  forAssets(...assets) {
    const assetList = assets.map((asset) => asset.toString()).join(",");
    this.url.searchParams.set("reserves", assetList);
    return this;
  }
  /**
   * Retrieves all pools an account is participating in.
   *
   * @param id - the participant account to filter by
   * @returns current LiquidityPoolCallBuilder instance
   */
  forAccount(id) {
    this.url.searchParams.set("account", id);
    return this;
  }
  /**
   * Retrieves a specific liquidity pool by ID.
   *
   * @param id - the hash/ID of the liquidity pool
   * @returns a new CallBuilder instance for the /liquidity_pools/:id endpoint
   */
  liquidityPoolId(id) {
    if (!id.match(/[a-fA-F0-9]{64}/)) {
      throw new TypeError(`${id} does not look like a liquidity pool ID`);
    }
    const builder = new call_builder.CallBuilder(
      new URL(this.url),
      this.httpClient
    );
    builder.filter.push([id.toLowerCase()]);
    return builder;
  }
}

exports.LiquidityPoolCallBuilder = LiquidityPoolCallBuilder;
//# sourceMappingURL=liquidity_pool_call_builder.js.map
