'use strict';

var call_builder = require('./call_builder.js');

class OrderbookCallBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient, selling, buying) {
    super(serverUrl, httpClient);
    this.setPath("order_book");
    const sellingIssuer = selling.getIssuer();
    if (!selling.isNative() && sellingIssuer !== void 0) {
      this.url.searchParams.set("selling_asset_type", selling.getAssetType());
      this.url.searchParams.set("selling_asset_code", selling.getCode());
      this.url.searchParams.set("selling_asset_issuer", sellingIssuer);
    } else {
      this.url.searchParams.set("selling_asset_type", "native");
    }
    const buyingIssuer = buying.getIssuer();
    if (!buying.isNative() && buyingIssuer !== void 0) {
      this.url.searchParams.set("buying_asset_type", buying.getAssetType());
      this.url.searchParams.set("buying_asset_code", buying.getCode());
      this.url.searchParams.set("buying_asset_issuer", buyingIssuer);
    } else {
      this.url.searchParams.set("buying_asset_type", "native");
    }
  }
}

exports.OrderbookCallBuilder = OrderbookCallBuilder;
//# sourceMappingURL=orderbook_call_builder.js.map
