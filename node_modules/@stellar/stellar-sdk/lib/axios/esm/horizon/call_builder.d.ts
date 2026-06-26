import { HorizonApi } from "./horizon_api.js";
import type { HttpClient } from "../http-client/index.js";
import { ServerApi } from "./server_api.js";
export interface EventSourceOptions<T> {
    onmessage?: (value: T extends ServerApi.CollectionPage<infer U> ? U : T) => void;
    onerror?: (event: MessageEvent) => void;
    reconnectTimeout?: number;
}
/**
 * Creates a new {@link CallBuilder} pointed to server defined by serverUrl.
 *
 * This is an **abstract** class. Do not create this object directly, use {@link Server} class.
 * @param serverUrl - URL of Horizon server
 */
export declare class CallBuilder<T extends HorizonApi.FeeStatsResponse | HorizonApi.BaseResponse | HorizonApi.RootResponse | ServerApi.CollectionPage<HorizonApi.BaseResponse>> {
    protected url: URL;
    filter: string[][];
    protected originalSegments: string[];
    protected neighborRoot: string;
    protected httpClient: HttpClient;
    constructor(serverUrl: URL, httpClient: HttpClient, neighborRoot?: string);
    protected setPath(...segments: string[]): void;
    /**
     * Triggers a HTTP request using this builder's current configuration.
     * @returns a Promise that resolves to the server's response.
     */
    call(): Promise<T>;
    /**
     * Creates an EventSource that listens for incoming messages from the server. To stop listening for new
     * events call the function returned by this method.
     * @see [Horizon Response Format](https://developers.stellar.org/api/introduction/response-format/)
     * @see [MDN EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource)
     * @param options - (optional) EventSource options.
     *   - `onmessage` (optional): Callback function to handle incoming messages.
     *   - `onerror` (optional): Callback function to handle errors.
     *   - `reconnectTimeout` (optional): Custom stream connection timeout in ms, default is 15 seconds.
     * @returns Close function. Run to close the connection and stop listening for new events.
     */
    stream(options?: EventSourceOptions<T extends ServerApi.CollectionPage<infer U> ? U : T>): () => void;
    /**
     * Sets `cursor` parameter for the current call. Returns the CallBuilder object on which this method has been called.
     * @see [Paging](https://developers.stellar.org/api/introduction/pagination/)
     * @param cursor - A cursor is a value that points to a specific location in a collection of resources.
     * @returns current CallBuilder instance
     */
    cursor(cursor: string): this;
    /**
     * Sets `limit` parameter for the current call. Returns the CallBuilder object on which this method has been called.
     * @see [Paging](https://developers.stellar.org/api/introduction/pagination/)
     * @param recordsNumber - Number of records the server should return.
     * @returns current CallBuilder instance
     */
    limit(recordsNumber: number): this;
    /**
     * Sets `order` parameter for the current call. Returns the CallBuilder object on which this method has been called.
     * @param direction - Sort direction
     * @returns current CallBuilder instance
     */
    order(direction: "asc" | "desc"): this;
    /**
     * Sets `join` parameter for the current call. The `join` parameter
     * includes the requested resource in the response. Currently, the
     * only valid value for the parameter is `transactions` and is only
     * supported on the operations and payments endpoints. The response
     * will include a `transaction` field for each operation in the
     * response.
     *
     * @param include - join Records to be included in the response.
     * @returns current CallBuilder instance.
     */
    join(include: "transactions"): this;
    /**
     * A helper method to craft queries to "neighbor" endpoints.
     *
     *  For example, we have an `/effects` suffix endpoint on many different
     *  "root" endpoints, such as `/transactions/:id` and `/accounts/:id`. So,
     *  it's helpful to be able to conveniently create queries to the
     *  `/accounts/:id/effects` endpoint:
     *
     *    `this.forEndpoint("accounts", accountId)`.
     *
     * @param endpoint - neighbor endpoint in question, like /operations
     * @param param - filter parameter, like an operation ID
     *
     * @returns this CallBuilder instance
     */
    protected forEndpoint(endpoint: string, param: string): this;
    /**
     * @hidden
     * @returns    */
    private checkFilter;
    /**
     * Convert a link object to a function that fetches that link.
     * @hidden
     * @param link - A link object
     *   - `href`: the URI of the link
     *   - `templated` (optional): Whether the link is templated
     * @returns A function that requests the link
     */
    private _requestFnForLink;
    /**
     * Given the json response, find and convert each link into a function that
     * calls that link.
     * @hidden
     * @param json - JSON response
     * @returns JSON response with string links replaced with functions
     */
    private _parseRecord;
    private _sendNormalRequest;
    /**
     * @hidden
     * @param json - Response object
     * @returns Extended response
     */
    private _parseResponse;
    /**
     * @hidden
     * @param json - Response object
     * @returns Extended response object
     */
    private _toCollectionPage;
    /**
     * @hidden
     * @param error - Network error object
     * @returns Promise that rejects with a human-readable error
     */
    private _handleNetworkError;
}
