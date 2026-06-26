import { CallBuilder } from './call_builder.js';

class TransactionCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient, "transactions");
    this.setPath("transactions");
  }
  /**
   * The transaction details endpoint provides information on a single transaction. The transaction hash provided in the hash argument specifies which transaction to load.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-transaction | Transaction Details}
   * @param transactionId - Transaction ID
   * @returns a CallBuilder instance
   */
  transaction(transactionId) {
    const builder = new CallBuilder(
      new URL(this.url),
      this.httpClient
    );
    builder.filter.push([transactionId]);
    return builder;
  }
  /**
   * This endpoint represents all transactions that affected a given account.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-transactions-by-account-id | Transactions for Account}
   * @param accountId - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current TransactionCallBuilder instance
   */
  forAccount(accountId) {
    return this.forEndpoint("accounts", accountId);
  }
  /**
   * This endpoint represents all transactions that reference a given claimable_balance.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/cb-retrieve-related-transactions | Transactions for Claimable Balance}
   * @param claimableBalanceId - Claimable Balance ID
   * @returns this TransactionCallBuilder instance
   */
  forClaimableBalance(claimableBalanceId) {
    return this.forEndpoint("claimable_balances", claimableBalanceId);
  }
  /**
   * This endpoint represents all transactions in a given ledger.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-ledgers-transactions | Transactions for Ledger}
   * @param sequence - Ledger sequence
   * @returns current TransactionCallBuilder instance
   */
  forLedger(sequence) {
    return this.forEndpoint("ledgers", sequence.toString());
  }
  /**
   * This endpoint represents all transactions involving a particular liquidity pool.
   *
   * @param poolId - liquidity pool ID
   * @returns this TransactionCallBuilder instance
   */
  forLiquidityPool(poolId) {
    return this.forEndpoint("liquidity_pools", poolId);
  }
  /**
   * Adds a parameter defining whether to include failed transactions. By default only successful transactions are
   * returned.
   * @param value - Set to `true` to include failed transactions.
   * @returns current TransactionCallBuilder instance
   */
  includeFailed(value) {
    this.url.searchParams.set("include_failed", value.toString());
    return this;
  }
}

export { TransactionCallBuilder };
//# sourceMappingURL=transaction_call_builder.js.map
