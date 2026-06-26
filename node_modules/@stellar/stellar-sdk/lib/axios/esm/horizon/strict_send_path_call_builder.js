import { CallBuilder } from './call_builder.js';

class StrictSendPathCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient, sourceAsset, sourceAmount, destination) {
    super(serverUrl, httpClient);
    this.setPath("paths/strict-send");
    const sourceIssuer = sourceAsset.getIssuer();
    if (sourceAsset.isNative()) {
      this.url.searchParams.set("source_asset_type", "native");
    } else if (sourceIssuer !== void 0) {
      this.url.searchParams.set(
        "source_asset_type",
        sourceAsset.getAssetType()
      );
      this.url.searchParams.set("source_asset_code", sourceAsset.getCode());
      this.url.searchParams.set("source_asset_issuer", sourceIssuer);
    }
    this.url.searchParams.set("source_amount", sourceAmount);
    if (typeof destination === "string") {
      this.url.searchParams.set("destination_account", destination);
    } else {
      const assets = destination.map((asset) => {
        if (asset.isNative()) {
          return "native";
        }
        return `${asset.getCode()}:${asset.getIssuer()}`;
      }).join(",");
      this.url.searchParams.set("destination_assets", assets);
    }
  }
}

export { StrictSendPathCallBuilder };
//# sourceMappingURL=strict_send_path_call_builder.js.map
