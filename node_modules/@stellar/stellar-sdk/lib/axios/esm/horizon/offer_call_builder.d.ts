import { Asset } from "../base/index.js";
import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link OfferCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.offers}.
 *
 * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/ | Offers}
 *
 * @param serverUrl - Horizon server URL.
 */
export declare class OfferCallBuilder extends CallBuilder<ServerApi.CollectionPage<ServerApi.OfferRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient);
    /**
     * The offer details endpoint provides information on a single offer. The offer ID provided in the id
     * argument specifies which offer to load.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/single/ | Offer Details}
     * @param offerId - Offer ID
     * @returns `CallBuilder<ServerApi.OfferRecord>` OperationCallBuilder instance
     */
    offer(offerId: string): CallBuilder<ServerApi.OfferRecord>;
    /**
     * Returns all offers where the given account is involved.
     *
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/accounts/offers/ | Offers}
     * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns current OfferCallBuilder instance
     */
    forAccount(id: string): this;
    /**
     * Returns all offers buying an asset.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/list/ | Offers}
     * @see Asset
     * @param asset - For example: `new Asset('USD','GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD')`
     * @returns current OfferCallBuilder instance
     */
    buying(asset: Asset): this;
    /**
     * Returns all offers selling an asset.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/offers/list/ | Offers}
     * @see Asset
     * @param asset - For example: `new Asset('EUR','GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD')`
     * @returns current OfferCallBuilder instance
     */
    selling(asset: Asset): this;
    /**
     * This endpoint filters offers where the given account is sponsoring the offer entry.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-all-offers | Offers}
     * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns current OfferCallBuilder instance
     */
    sponsor(id: string): this;
    /**
     * This endpoint filters offers where the given account is the seller.
     *
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-all-offers | Offers}
     * @param seller - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns current OfferCallBuilder instance
     */
    seller(seller: string): this;
}
