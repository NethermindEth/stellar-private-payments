'use strict';

var call_builder = require('./call_builder.js');
var bad_request = require('../errors/bad_request.js');

const allowedResolutions = [
  6e4,
  3e5,
  9e5,
  36e5,
  864e5,
  6048e5
];
class TradeAggregationCallBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient, base, counter, start_time, end_time, resolution, offset) {
    super(serverUrl, httpClient);
    this.setPath("trade_aggregations");
    const baseIssuer = base.getIssuer();
    if (!base.isNative() && baseIssuer !== void 0) {
      this.url.searchParams.set("base_asset_type", base.getAssetType());
      this.url.searchParams.set("base_asset_code", base.getCode());
      this.url.searchParams.set("base_asset_issuer", baseIssuer);
    } else {
      this.url.searchParams.set("base_asset_type", "native");
    }
    const counterIssuer = counter.getIssuer();
    if (!counter.isNative() && counterIssuer !== void 0) {
      this.url.searchParams.set("counter_asset_type", counter.getAssetType());
      this.url.searchParams.set("counter_asset_code", counter.getCode());
      this.url.searchParams.set("counter_asset_issuer", counterIssuer);
    } else {
      this.url.searchParams.set("counter_asset_type", "native");
    }
    if (typeof start_time !== "number" || typeof end_time !== "number") {
      throw new bad_request.BadRequestError("Invalid time bounds", [start_time, end_time]);
    } else {
      this.url.searchParams.set("start_time", start_time.toString());
      this.url.searchParams.set("end_time", end_time.toString());
    }
    if (!this.isValidResolution(resolution)) {
      throw new bad_request.BadRequestError("Invalid resolution", resolution);
    } else {
      this.url.searchParams.set("resolution", resolution.toString());
    }
    if (!this.isValidOffset(offset, resolution)) {
      throw new bad_request.BadRequestError("Invalid offset", offset);
    } else {
      this.url.searchParams.set("offset", offset.toString());
    }
  }
  /**
   * @hidden
   * @param resolution - Trade data resolution in milliseconds
   * @returns true if the resolution is allowed
   */
  isValidResolution(resolution) {
    return allowedResolutions.some((allowed) => allowed === resolution);
  }
  /**
   * @hidden
   * @param offset - Time offset in milliseconds
   * @param resolution - Trade data resolution in milliseconds
   * @returns true if the offset is valid
   */
  isValidOffset(offset, resolution) {
    const hour = 36e5;
    return !(offset > resolution || offset >= 24 * hour || offset % hour !== 0);
  }
}

exports.TradeAggregationCallBuilder = TradeAggregationCallBuilder;
//# sourceMappingURL=trade_aggregation_call_builder.js.map
