import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link AssetsCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.assets}.
 *
 * @param serverUrl - Horizon server URL.
 */
export declare class AssetsCallBuilder extends CallBuilder<ServerApi.CollectionPage<ServerApi.AssetRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient);
    /**
     * This endpoint filters all assets by the asset code.
     * @param value - For example: `USD`
     * @returns current AssetCallBuilder instance
     */
    forCode(value: string): AssetsCallBuilder;
    /**
     * This endpoint filters all assets by the asset issuer.
     * @param value - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns current AssetCallBuilder instance
     */
    forIssuer(value: string): AssetsCallBuilder;
}
