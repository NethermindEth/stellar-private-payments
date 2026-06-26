import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link PaymentCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.payments}.
 *
 * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/horizon/resources/list-all-payments/ | All Payments}
 *
 * @param serverUrl - Horizon server URL.
 */
export declare class PaymentCallBuilder extends CallBuilder<ServerApi.CollectionPage<ServerApi.PaymentOperationRecord | ServerApi.CreateAccountOperationRecord | ServerApi.AccountMergeOperationRecord | ServerApi.PathPaymentOperationRecord | ServerApi.PathPaymentStrictSendOperationRecord | ServerApi.InvokeHostFunctionOperationRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient);
    /**
     * This endpoint responds with a collection of Payment operations where the given account was either the sender or receiver.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/horizon/resources/get-payments-by-account-id | Payments for Account}
     * @param accountId - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns this PaymentCallBuilder instance
     */
    forAccount(accountId: string): this;
    /**
     * This endpoint represents all payment operations that are part of a valid transactions in a given ledger.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/horizon/resources/retrieve-a-ledgers-payments | Payments for Ledger}
     * @param sequence - Ledger sequence
     * @returns this PaymentCallBuilder instance
     */
    forLedger(sequence: number | string): this;
    /**
     * This endpoint represents all payment operations that are part of a given transaction.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/transactions/payments/ | Payments for Transaction}
     * @param transactionId - Transaction ID
     * @returns this PaymentCallBuilder instance
     */
    forTransaction(transactionId: string): this;
    /**
     * Adds a parameter defining whether to include failed transactions.
     *   By default, only operations of successful transactions are returned.
     *
     * @param value - Set to `true` to include operations of failed transactions.
     * @returns this PaymentCallBuilder instance
     */
    includeFailed(value: boolean): this;
}
