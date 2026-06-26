'use strict';

var call_builder = require('./call_builder.js');

class StrictReceivePathCallBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient, source, destinationAsset, destinationAmount) {
    super(serverUrl, httpClient);
    this.setPath("paths/strict-receive");
    if (typeof source === "string") {
      this.url.searchParams.set("source_account", source);
    } else {
      const assets = source.map((asset) => {
        if (asset.isNative()) {
          return "native";
        }
        return `${asset.getCode()}:${asset.getIssuer()}`;
      }).join(",");
      this.url.searchParams.set("source_assets", assets);
    }
    this.url.searchParams.set("destination_amount", destinationAmount);
    const issuer = destinationAsset.getIssuer();
    if (!destinationAsset.isNative() && issuer !== void 0) {
      this.url.searchParams.set(
        "destination_asset_type",
        destinationAsset.getAssetType()
      );
      this.url.searchParams.set(
        "destination_asset_code",
        destinationAsset.getCode()
      );
      this.url.searchParams.set("destination_asset_issuer", issuer);
    } else {
      this.url.searchParams.set("destination_asset_type", "native");
    }
  }
}

exports.StrictReceivePathCallBuilder = StrictReceivePathCallBuilder;
//# sourceMappingURL=strict_receive_path_call_builder.js.map
