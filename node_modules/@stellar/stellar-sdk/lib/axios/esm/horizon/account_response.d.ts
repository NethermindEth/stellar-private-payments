import type { TransactionSource } from "../base/index.js";
import { HorizonApi } from "./horizon_api.js";
import { ServerApi } from "./server_api.js";
/**
 * Do not create this object directly, use {@link Horizon.Server.loadAccount | Horizon.Server#loadAccount}.
 *
 * Returns information and links relating to a single account.
 * The balances section in the returned JSON will also list all the trust lines this account has set up.
 * It also contains {@link BaseAccount} object and exposes it's methods so can be used in {@link TransactionBuilder}.
 *
 * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/accounts/object | Account Details}
 * @param response - Response from horizon account endpoint.
 * @returns AccountResponse instance
 */
export declare class AccountResponse implements TransactionSource {
    readonly id: string;
    readonly paging_token: string;
    readonly account_id: string;
    sequence: string;
    readonly sequence_ledger?: number;
    readonly sequence_time?: string;
    readonly subentry_count: number;
    readonly home_domain?: string;
    readonly inflation_destination?: string;
    readonly last_modified_ledger: number;
    readonly last_modified_time: string;
    readonly thresholds: HorizonApi.AccountThresholds;
    readonly flags: HorizonApi.Flags;
    readonly balances: HorizonApi.BalanceLine[];
    readonly signers: ServerApi.AccountRecordSigners[];
    readonly num_sponsoring: number;
    readonly num_sponsored: number;
    readonly sponsor?: string;
    readonly data: (options: {
        value: string;
    }) => Promise<{
        value: string;
    }>;
    readonly data_attr: Record<string, string>;
    readonly effects: ServerApi.CallCollectionFunction<ServerApi.EffectRecord>;
    readonly offers: ServerApi.CallCollectionFunction<ServerApi.OfferRecord>;
    readonly operations: ServerApi.CallCollectionFunction<ServerApi.OperationRecord>;
    readonly payments: ServerApi.CallCollectionFunction<ServerApi.PaymentOperationRecord>;
    readonly trades: ServerApi.CallCollectionFunction<ServerApi.TradeRecord>;
    readonly transactions: ServerApi.CallCollectionFunction<ServerApi.TransactionRecord>;
    private readonly _baseAccount;
    constructor(response: ServerApi.AccountRecord);
    /**
     * Get Stellar account public key ex. `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`
     * @returns accountId
     */
    accountId(): string;
    /**
     * Get the current sequence number
     * @returns sequenceNumber
     */
    sequenceNumber(): string;
    /**
     * Increments sequence number in this object by one.
     * @returns    */
    incrementSequenceNumber(): void;
}
