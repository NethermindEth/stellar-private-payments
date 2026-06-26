import { CallBuilder } from "./call_builder.js";
import { ServerApi } from "./server_api.js";
import type { HttpClient } from "../http-client/index.js";
/**
 * Creates a new {@link OperationCallBuilder} pointed to server defined by serverUrl.
 *
 * Do not create this object directly, use {@link Horizon.Server.operations}.
 *
 * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/operations | All Operations}
 *
 * @param serverUrl - Horizon server URL.
 */
export declare class OperationCallBuilder extends CallBuilder<ServerApi.CollectionPage<ServerApi.OperationRecord>> {
    constructor(serverUrl: URL, httpClient: HttpClient);
    /**
     * The operation details endpoint provides information on a single operation. The operation ID provided in the id
     * argument specifies which operation to load.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-an-operation | Operation Details}
     * @param operationId - Operation ID
     * @returns this OperationCallBuilder instance
     */
    operation(operationId: string): CallBuilder<ServerApi.OperationRecord>;
    /**
     * This endpoint represents all operations that were included in valid transactions that affected a particular account.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-operations-by-account-id | Operations for Account}
     * @param accountId - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
     * @returns this OperationCallBuilder instance
     */
    forAccount(accountId: string): this;
    /**
     * This endpoint represents all operations that reference a given claimable_balance.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/cb-retrieve-related-operations | Operations for Claimable Balance}
     * @param claimableBalanceId - Claimable Balance ID
     * @returns this OperationCallBuilder instance
     */
    forClaimableBalance(claimableBalanceId: string): this;
    /**
     * This endpoint returns all operations that occurred in a given ledger.
     *
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-ledgers-operations | Operations for Ledger}
     * @param sequence - Ledger sequence
     * @returns this OperationCallBuilder instance
     */
    forLedger(sequence: number | string): this;
    /**
     * This endpoint represents all operations that are part of a given transaction.
     * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-transactions-operations | Operations for Transaction}
     * @param transactionId - Transaction ID
     * @returns this OperationCallBuilder instance
     */
    forTransaction(transactionId: string): this;
    /**
     * This endpoint represents all operations involving a particular liquidity pool.
     *
     * @param poolId - liquidity pool ID
     * @returns this OperationCallBuilder instance
     */
    forLiquidityPool(poolId: string): this;
    /**
     * Adds a parameter defining whether to include failed transactions.
     *   By default, only operations of successful transactions are returned.
     *
     * @param value - Set to `true` to include operations of failed transactions.
     * @returns this OperationCallBuilder instance
     */
    includeFailed(value: boolean): this;
}
