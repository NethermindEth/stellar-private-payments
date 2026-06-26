import { CallBuilder } from './call_builder.js';

class ClaimableBalanceCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient);
    this.setPath("claimable_balances");
  }
  /**
   * The claimable balance details endpoint provides information on a single claimable balance.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-a-claimable-balance | Claimable Balance Details}
   * @param claimableBalanceId - Claimable balance ID
   * @returns `CallBuilder<ServerApi.ClaimableBalanceRecord>` OperationCallBuilder instance
   */
  claimableBalance(claimableBalanceId) {
    const builder = new CallBuilder(
      new URL(this.url),
      this.httpClient
    );
    builder.filter.push([claimableBalanceId]);
    return builder;
  }
  /**
   * Returns all claimable balances which are sponsored by the given account ID.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-claimable-balances | Claimable Balances}
   * @param sponsor - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current ClaimableBalanceCallBuilder instance
   */
  sponsor(sponsor) {
    this.url.searchParams.set("sponsor", sponsor);
    return this;
  }
  /**
   * Returns all claimable balances which can be claimed by the given account ID.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-claimable-balances | Claimable Balances}
   * @param claimant - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current ClaimableBalanceCallBuilder instance
   */
  claimant(claimant) {
    this.url.searchParams.set("claimant", claimant);
    return this;
  }
  /**
   * Returns all claimable balances which provide a balance for the given asset.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-claimable-balances | Claimable Balances}
   * @param asset - The Asset held by the claimable balance
   * @returns current ClaimableBalanceCallBuilder instance
   */
  asset(asset) {
    this.url.searchParams.set("asset", asset.toString());
    return this;
  }
}

export { ClaimableBalanceCallBuilder };
//# sourceMappingURL=claimable_balances_call_builder.js.map
