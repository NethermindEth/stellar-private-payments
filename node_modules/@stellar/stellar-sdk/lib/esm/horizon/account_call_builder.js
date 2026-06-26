import { CallBuilder } from './call_builder.js';

class AccountCallBuilder extends CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient);
    this.setPath("accounts");
  }
  /**
   * Returns information and links relating to a single account.
   * The balances section in the returned JSON will also list all the trust lines this account has set up.
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/retrieve-an-account | Account Details}
   * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns a new CallBuilder instance for the /accounts/:id endpoint
   */
  accountId(id) {
    const builder = new CallBuilder(
      new URL(this.url),
      this.httpClient
    );
    builder.filter.push([id]);
    return builder;
  }
  /**
   * This endpoint filters accounts by signer account.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-accounts | Accounts}
   * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current AccountCallBuilder instance
   */
  forSigner(id) {
    this.url.searchParams.set("signer", id);
    return this;
  }
  /**
   * This endpoint filters all accounts who are trustees to an asset.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-accounts | Accounts}
   * @see Asset
   * @param asset - For example: `new Asset('USD','GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD')`
   * @returns current AccountCallBuilder instance
   */
  forAsset(asset) {
    this.url.searchParams.set("asset", `${asset}`);
    return this;
  }
  /**
   * This endpoint filters accounts where the given account is sponsoring the account or any of its sub-entries..
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/list-all-accounts | Accounts}
   * @param id - For example: `GDGQVOKHW4VEJRU2TETD6DBRKEO5ERCNF353LW5WBFW3JJWQ2BRQ6KDD`
   * @returns current AccountCallBuilder instance
   */
  sponsor(id) {
    this.url.searchParams.set("sponsor", id);
    return this;
  }
  /**
   * This endpoint filters accounts holding a trustline to the given liquidity pool.
   *
   * @param id - The ID of the liquidity pool. For example: `dd7b1ab831c273310ddbec6f97870aa83c2fbd78ce22aded37ecbf4f3380fac7`.
   * @returns current AccountCallBuilder instance
   */
  forLiquidityPool(id) {
    this.url.searchParams.set("liquidity_pool", id);
    return this;
  }
}

export { AccountCallBuilder };
//# sourceMappingURL=account_call_builder.js.map
