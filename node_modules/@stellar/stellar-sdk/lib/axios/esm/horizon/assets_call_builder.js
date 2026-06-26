import { CallBuilder } from './call_builder.js';

class AssetsCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient);
    this.setPath("assets");
  }
  /**
   * This endpoint filters all assets by the asset code.
   * @param value - For example: `USD`
   * @returns current AssetCallBuilder instance
   */
  forCode(value) {
    this.url.searchParams.set("asset_code", value);
    return this;
  }
  /**
   * This endpoint filters all assets by the asset issuer.
   * @param value - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current AssetCallBuilder instance
   */
  forIssuer(value) {
    this.url.searchParams.set("asset_issuer", value);
    return this;
  }
}

export { AssetsCallBuilder };
//# sourceMappingURL=assets_call_builder.js.map
