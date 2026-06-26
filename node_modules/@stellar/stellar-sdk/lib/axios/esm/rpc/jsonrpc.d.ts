import type { HttpClient } from "../http-client/index.js";
export type Id = string | number;
export interface Request<T> {
    jsonrpc: "2.0";
    id: Id;
    method: string;
    params: T;
}
export interface Notification<T> {
    jsonrpc: "2.0";
    method: string;
    params?: T;
}
export type Response<T, E = any> = {
    jsonrpc: "2.0";
    id: Id;
} & ({
    error: Error<E>;
} | {
    result: T;
});
export interface Error<E = any> {
    code: number;
    message?: string;
    data?: E;
}
/**
 * Sends the jsonrpc 'params' as a single 'param' object (no array support).
 *
 * @param client - HttpClient instance to use for the request
 * @param url - URL to the RPC instance
 * @param method - RPC method name that should be called
 * @param param - (optional) params that should be supplied to the method
 * @returns Promise that resolves to the result of type T
 * @hidden
 */
export declare function postObject<T>(client: HttpClient, url: string, method: string, param?: any): Promise<T>;
