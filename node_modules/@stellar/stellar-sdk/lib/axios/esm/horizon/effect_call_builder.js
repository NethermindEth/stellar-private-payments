import { CallBuilder } from './call_builder.js';

class EffectCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient, "effects");
    this.setPath("effects");
  }
  /**
   * This endpoint represents all effects that changed a given account. It will return relevant effects from the creation of the account to the current ledger.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/get-effects-by-account-id | Effects for Account}
   * @param accountId - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns this EffectCallBuilder instance
   */
  forAccount(accountId) {
    return this.forEndpoint("accounts", accountId);
  }
  /**
   * Effects are the specific ways that the ledger was changed by any operation.
   *
   * This endpoint represents all effects that occurred in the given ledger.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-ledgers-effects | Effects for Ledger}
   * @param sequence - Ledger sequence
   * @returns this EffectCallBuilder instance
   */
  forLedger(sequence) {
    return this.forEndpoint("ledgers", sequence.toString());
  }
  /**
   * This endpoint represents all effects that occurred as a result of a given transaction.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-transactions-effects | Effects for Transaction}
   * @param transactionId - Transaction ID
   * @returns this EffectCallBuilder instance
   */
  forTransaction(transactionId) {
    return this.forEndpoint("transactions", transactionId);
  }
  /**
   * This endpoint represents all effects that occurred as a result of a given operation.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-an-operations-effects | Effects for Operation}
   * @param operationId - Operation ID
   * @returns this EffectCallBuilder instance
   */
  forOperation(operationId) {
    return this.forEndpoint("operations", operationId);
  }
  /**
   * This endpoint represents all effects involving a particular liquidity pool.
   *
   * @param poolId - liquidity pool ID
   * @returns this EffectCallBuilder instance
   */
  forLiquidityPool(poolId) {
    return this.forEndpoint("liquidity_pools", poolId);
  }
}

export { EffectCallBuilder };
//# sourceMappingURL=effect_call_builder.js.map
