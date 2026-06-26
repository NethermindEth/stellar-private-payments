import { CallBuilder } from "./call_builder.js";
import type { HttpClient } from "../http-client/index.js";
export declare class FriendbotBuilder extends CallBuilder<any> {
    constructor(serverUrl: URL, httpClient: HttpClient, address: string);
}
