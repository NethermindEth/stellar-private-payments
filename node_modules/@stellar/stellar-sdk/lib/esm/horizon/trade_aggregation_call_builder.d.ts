import { Asset } from "../base/index.js";
import { CallBuilder } from "./call_builder.js";
import { HorizonApi } from "./horizon_api.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Trade Aggregations facilitate efficient gathering of historical trade data.
 *
 * Do not create this object directly, use {@link Horizon.Server.tradeAggregation}.
 *
 * @param serverUrl - serverUrl Horizon server URL.
 * @param base - base asset
 * @param counter - counter asset
 * @param start_time - lower time boundary represented as millis since epoch
 * @param end_time - upper time boundary represented as millis since epoch
 * @param resolution - segment duration as millis since epoch. *Supported values are 1 minute (60000), 5 minutes (300000), 15 minutes (900000), 1 hour (3600000), 1 day (86400000) and 1 week (604800000).
 * @param offset - segments can be offset using this parameter. Expressed in milliseconds. *Can only be used if the resolution is greater than 1 hour. Value must be in whole hours, less than the provided resolution, and less than 24 hours.
 */
export declare class TradeAggregationCallBuilder extends CallBuilder<ServerApi.CollectionPage<TradeAggregationRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient, base: Asset, counter: Asset, start_time: number, end_time: number, resolution: number, offset: number);
    /**
     * @hidden
     * @param resolution - Trade data resolution in milliseconds
     * @returns true if the resolution is allowed
     */
    private isValidResolution;
    /**
     * @hidden
     * @param offset - Time offset in milliseconds
     * @param resolution - Trade data resolution in milliseconds
     * @returns true if the offset is valid
     */
    private isValidOffset;
}
interface TradeAggregationRecord extends HorizonApi.BaseResponse {
    timestamp: number | string;
    trade_count: number | string;
    base_volume: string;
    counter_volume: string;
    avg: string;
    high: string;
    low: string;
    open: string;
    close: string;
}
export {};
