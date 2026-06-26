import { type HttpClient } from "../http-client/index.js";
export declare const version: string;
export declare function createHttpClient(headers?: Record<string, string>): HttpClient;
