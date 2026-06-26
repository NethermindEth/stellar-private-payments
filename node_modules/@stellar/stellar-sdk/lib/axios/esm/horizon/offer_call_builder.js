import { CallBuilder } from './call_builder.js';

class OfferCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient, "offers");
    this.setPath("offers");
  }
  /**
   * The offer details endpoint provides information on a single offer. The offer ID provided in the id
   * argument specifies which offer to load.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/single/ | Offer Details}
   * @param offerId - Offer ID
   * @returns `CallBuilder<ServerApi.OfferRecord>` OperationCallBuilder instance
   */
  offer(offerId) {
    const builder = new CallBuilder(
      new URL(this.url),
      this.httpClient
    );
    builder.filter.push([offerId]);
    return builder;
  }
  /**
   * Returns all offers where the given account is involved.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/accounts/offers/ | Offers}
   * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current OfferCallBuilder instance
   */
  forAccount(id) {
    return this.forEndpoint("accounts", id);
  }
  /**
   * Returns all offers buying an asset.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/list/ | Offers}
   * @see Asset
   * @param asset - For example: `new Asset('USD','GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD')`
   * @returns current OfferCallBuilder instance
   */
  buying(asset) {
    const issuer = asset.getIssuer();
    if (!asset.isNative() && issuer !== void 0) {
      this.url.searchParams.set("buying_asset_type", asset.getAssetType());
      this.url.searchParams.set("buying_asset_code", asset.getCode());
      this.url.searchParams.set("buying_asset_issuer", issuer);
    } else {
      this.url.searchParams.set("buying_asset_type", "native");
    }
    return this;
  }
  /**
   * Returns all offers selling an asset.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/list/ | Offers}
   * @see Asset
   * @param asset - For example: `new Asset('EUR','GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD')`
   * @returns current OfferCallBuilder instance
   */
  selling(asset) {
    const issuer = asset.getIssuer();
    if (!asset.isNative() && issuer !== void 0) {
      this.url.searchParams.set("selling_asset_type", asset.getAssetType());
      this.url.searchParams.set("selling_asset_code", asset.getCode());
      this.url.searchParams.set("selling_asset_issuer", issuer);
    } else {
      this.url.searchParams.set("selling_asset_type", "native");
    }
    return this;
  }
  /**
   * This endpoint filters offers where the given account is sponsoring the offer entry.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-all-offers | Offers}
   * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current OfferCallBuilder instance
   */
  sponsor(id) {
    this.url.searchParams.set("sponsor", id);
    return this;
  }
  /**
   * This endpoint filters offers where the given account is the seller.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-all-offers | Offers}
   * @param seller - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current OfferCallBuilder instance
   */
  seller(seller) {
    this.url.searchParams.set("seller", seller);
    return this;
  }
}

export { OfferCallBuilder };
//# sourceMappingURL=offer_call_builder.js.map
