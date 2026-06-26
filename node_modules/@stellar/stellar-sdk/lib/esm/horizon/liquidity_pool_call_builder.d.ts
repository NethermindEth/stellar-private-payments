import { Asset } from "../base/index.js";
import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link LiquidityPoolCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.liquidityPools}.
 *
 * @param serverUrl - Horizon server URL.
 */
export declare class LiquidityPoolCallBuilder extends CallBuilder<ServerApi.CollectionPage<ServerApi.LiquidityPoolRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient);
    /**
     * Filters out pools whose reserves don't exactly match these assets.
     *
     * @see Asset
     * @returns current LiquidityPoolCallBuilder instance
     */
    forAssets(...assets: Asset[]): this;
    /**
     * Retrieves all pools an account is participating in.
     *
     * @param id - the participant account to filter by
     * @returns current LiquidityPoolCallBuilder instance
     */
    forAccount(id: string): this;
    /**
     * Retrieves a specific liquidity pool by ID.
     *
     * @param id - the hash/ID of the liquidity pool
     * @returns a new CallBuilder instance for the /liquidity_pools/:id endpoint
     */
    liquidityPoolId(id: string): CallBuilder<ServerApi.LiquidityPoolRecord>;
}
