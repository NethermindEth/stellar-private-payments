import { Asset } from "../base/index.js";
import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link OrderbookCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.orderbook}.
 *
 * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/aggregations/order-books | Orderbook Details}
 *
 * @param serverUrl - serverUrl Horizon server URL.
 * @param selling - Asset being sold
 * @param buying - Asset being bought
 */
export declare class OrderbookCallBuilder extends CallBuilder<ServerApi.OrderbookRecord> {
    constructor(serverUrl: URL, httpClient: HttpClient, selling: Asset, buying: Asset);
}
