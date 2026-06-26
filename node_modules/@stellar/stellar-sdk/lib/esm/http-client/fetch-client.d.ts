import type { AxiosRequestConfig, AxiosResponse } from "feaxios";
import { CancelToken, type HttpClient, type HttpClientRequestConfig, type HttpClientResponse } from "./types.js";
export interface HttpResponse<T = any> extends AxiosResponse<T> {
}
export interface FetchClientConfig<T = any> extends AxiosRequestConfig {
    adapter?: (config: HttpClientRequestConfig) => Promise<HttpClientResponse<T>>;
    cancelToken?: CancelToken;
}
declare function createFetchClient(fetchConfig?: HttpClientRequestConfig): HttpClient;
export declare const fetchClient: HttpClient;
export { createFetchClient as create };
