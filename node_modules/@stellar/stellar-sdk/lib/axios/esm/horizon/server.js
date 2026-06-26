import BigNumber from '../base/util/bignumber.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import types from '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import { Asset } from '../base/asset.js';
import '../base/keypair.js';
import { StrKey } from '../base/strkey.js';
import '../base/util/continued_fraction.js';
import { FeeBumpTransaction } from '../base/fee_bump_transaction.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';
import { CallBuilder } from './call_builder.js';
import { Config } from '../config.js';
import { NotFoundError } from '../errors/not_found.js';
import { BadResponseError } from '../errors/bad_response.js';
import { AccountRequiresMemoError } from '../errors/account_requires_memo.js';
import { AccountCallBuilder } from './account_call_builder.js';
import { AccountResponse } from './account_response.js';
import { AssetsCallBuilder } from './assets_call_builder.js';
import { ClaimableBalanceCallBuilder } from './claimable_balances_call_builder.js';
import { EffectCallBuilder } from './effect_call_builder.js';
import { FriendbotBuilder } from './friendbot_builder.js';
import { LedgerCallBuilder } from './ledger_call_builder.js';
import { LiquidityPoolCallBuilder } from './liquidity_pool_call_builder.js';
import { OfferCallBuilder } from './offer_call_builder.js';
import { OperationCallBuilder } from './operation_call_builder.js';
import { OrderbookCallBuilder } from './orderbook_call_builder.js';
import { PaymentCallBuilder } from './payment_call_builder.js';
import { StrictReceivePathCallBuilder } from './strict_receive_path_call_builder.js';
import { StrictSendPathCallBuilder } from './strict_send_path_call_builder.js';
import { TradeAggregationCallBuilder } from './trade_aggregation_call_builder.js';
import { TradesCallBuilder } from './trades_call_builder.js';
import { TransactionCallBuilder } from './transaction_call_builder.js';
import { createHttpClient, getCurrentServerTime } from './horizon_axios_client.js';

const SUBMIT_TRANSACTION_TIMEOUT = 60 * 1e3;
const STROOPS_IN_LUMEN = 1e7;
const ACCOUNT_REQUIRES_MEMO = "MQ==";
function getAmountInLumens(amt) {
  return new BigNumber(amt).div(STROOPS_IN_LUMEN).toString();
}
class HorizonServer {
  /**
   * Horizon Server URL (ex. `https://horizon-testnet.stellar.org`)
   *
   * TODO: Solve `this.serverURL`.
   */
  serverURL;
  /**
   * HTTP client instance for making requests to Horizon.
   * Exposes interceptors, defaults, and other configuration options.
   *
   * @example
   * ```ts
   * // Add authentication header
   * server.httpClient.defaults.headers['Authorization'] = 'Bearer token';
   *
   * // Add request interceptor
   * server.httpClient.interceptors.request.use((config) => {
   *   console.log('Request:', config.url);
   *   return config;
   * });
   * ```
   */
  httpClient;
  constructor(serverURL, opts = {}) {
    this.serverURL = new URL(serverURL);
    const allowHttp = typeof opts.allowHttp === "undefined" ? Config.isAllowHttp() : opts.allowHttp;
    const customHeaders = {};
    if (opts.appName) {
      customHeaders["X-App-Name"] = opts.appName;
    }
    if (opts.appVersion) {
      customHeaders["X-App-Version"] = opts.appVersion;
    }
    if (opts.authToken) {
      customHeaders["X-Auth-Token"] = opts.authToken;
    }
    if (opts.headers) {
      Object.assign(customHeaders, opts.headers);
    }
    this.httpClient = createHttpClient(customHeaders);
    if (this.serverURL.protocol !== "https:" && !allowHttp) {
      throw new Error("Cannot connect to insecure horizon server");
    }
  }
  /**
   * Get timebounds for N seconds from now, when you're creating a transaction
   * with {@link TransactionBuilder}.
   *
   * By default, {@link TransactionBuilder} uses the current local time, but
   * your machine's local time could be different from Horizon's. This gives you
   * more assurance that your timebounds will reflect what you want.
   *
   * Note that this will generate your timebounds when you **init the transaction**,
   * not when you build or submit the transaction! So give yourself enough time to get
   * the transaction built and signed before submitting.
   *
   * @example
   * ```ts
   * const transaction = new StellarSdk.TransactionBuilder(accountId, {
   *   fee: await StellarSdk.Server.fetchBaseFee(),
   *   timebounds: await StellarSdk.Server.fetchTimebounds(100)
   * })
   *   .addOperation(operation)
   *   // normally we would need to call setTimeout here, but setting timebounds
   *   // earlier does the trick!
   *   .build();
   * ```
   *
   * @param seconds - Number of seconds past the current time to wait.
   * @param _isRetry - (optional) True if this is a retry. Only set this internally!
   * This is to avoid a scenario where Horizon is horking up the wrong date.
   * @returns Promise that resolves a `Timebounds` object
   * (with the shape `{ minTime: 0, maxTime: N }`) that you can set the `timebounds` option to.
   */
  async fetchTimebounds(seconds, _isRetry = false) {
    const serverPort = this.serverURL.port;
    const serverKey = serverPort ? `${this.serverURL.hostname}:${serverPort}` : this.serverURL.hostname;
    const currentTime = getCurrentServerTime(serverKey);
    if (currentTime) {
      return {
        minTime: 0,
        maxTime: currentTime + seconds
      };
    }
    if (_isRetry) {
      return {
        minTime: 0,
        maxTime: Math.floor((/* @__PURE__ */ new Date()).getTime() / 1e3) + seconds
      };
    }
    await this.httpClient.get(this.serverURL.toString());
    return this.fetchTimebounds(seconds, true);
  }
  /**
   * Fetch the base fee. Since this hits the server, if the server call fails,
   * you might get an error. You should be prepared to use a default value if
   * that happens!
   * @returns Promise that resolves to the base fee.
   */
  async fetchBaseFee() {
    const response = await this.feeStats();
    return parseInt(response.last_ledger_base_fee, 10) || 100;
  }
  /**
   * Fetch the fee stats endpoint.
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/aggregations/fee-stats | Fee Stats}
   * @returns Promise that resolves to the fee stats returned by Horizon.
   */
  async feeStats() {
    const cb = new CallBuilder(
      this.serverURL,
      this.httpClient
    );
    cb.filter.push(["fee_stats"]);
    return cb.call();
  }
  /**
   * Fetch the Horizon server's root endpoint.
   * @returns Promise that resolves to the root endpoint returned by Horizon.
   */
  async root() {
    const cb = new CallBuilder(
      this.serverURL,
      this.httpClient
    );
    return cb.call();
  }
  /**
   * Submits a transaction to the network.
   *
   * By default this function calls {@link Horizon.Server.checkMemoRequired}, you can
   * skip this check by setting the option `skipMemoRequiredCheck` to `true`.
   *
   * If you submit any number of `manageOffer` operations, this will add an
   * attribute to the response that will help you analyze what happened with
   * your offers.
   *
   * For example, you'll want to examine `offerResults` to add affordances like
   * these to your app:
   * - If `wasImmediatelyFilled` is true, then no offer was created. So if you
   *   normally watch the `Server.offers` endpoint for offer updates, you
   *   instead need to check `Server.trades` to find the result of this filled
   *   offer.
   * - If `wasImmediatelyDeleted` is true, then the offer you submitted was
   *   deleted without reaching the orderbook or being matched (possibly because
   *   your amounts were rounded down to zero). So treat the just-submitted
   *   offer request as if it never happened.
   * - If `wasPartiallyFilled` is true, you can tell the user that
   *   `amountBought` or `amountSold` have already been transferred.
   *
   * @example
   * ```ts
   * const res = {
   *   ...response,
   *   offerResults: [
   *     {
   *       // Exact ordered list of offers that executed, with the exception
   *       // that the last one may not have executed entirely.
   *       offersClaimed: [
   *         sellerId: String,
   *         offerId: String,
   *         assetSold: {
   *           type: 'native|credit_alphanum4|credit_alphanum12',
   *
   *           // these are only present if the asset is not native
   *           assetCode: String,
   *           issuer: String,
   *         },
   *
   *         // same shape as assetSold
   *         assetBought: {}
   *       ],
   *
   *       // What effect your manageOffer op had
   *       effect: "manageOfferCreated|manageOfferUpdated|manageOfferDeleted",
   *
   *       // Whether your offer immediately got matched and filled
   *       wasImmediatelyFilled: Boolean,
   *
   *       // Whether your offer immediately got deleted, if for example the order was too small
   *       wasImmediatelyDeleted: Boolean,
   *
   *       // Whether the offer was partially, but not completely, filled
   *       wasPartiallyFilled: Boolean,
   *
   *       // The full requested amount of the offer is open for matching
   *       isFullyOpen: Boolean,
   *
   *       // The total amount of tokens bought / sold during transaction execution
   *       amountBought: Number,
   *       amountSold: Number,
   *
   *       // if the offer was created, updated, or partially filled, this is
   *       // the outstanding offer
   *       currentOffer: {
   *         offerId: String,
   *         amount: String,
   *         price: {
   *           n: String,
   *           d: String,
   *         },
   *
   *         selling: {
   *           type: 'native|credit_alphanum4|credit_alphanum12',
   *
   *           // these are only present if the asset is not native
   *           assetCode: String,
   *           issuer: String,
   *         },
   *
   *         // same as `selling`
   *         buying: {},
   *       },
   *
   *       // the index of this particular operation in the op stack
   *       operationIndex: Number
   *     }
   *   ]
   * }
   * ```
   *
   * @see {@link https://developers.stellar.org/docs/data/horizon/api-reference/resources/submit-a-transaction | Submit a Transaction}
   * @param transaction - The transaction to submit.
   * @param opts - (optional) Options object
   *   - `skipMemoRequiredCheck` (optional): Allow skipping memo
   * required check, default: `false`. See
   * [SEP0029](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0029.md).
   * @returns Promise that resolves or rejects with response from
   * horizon.
   */
  async submitTransaction(transaction, opts = {
    skipMemoRequiredCheck: false
  }) {
    if (!opts.skipMemoRequiredCheck) {
      await this.checkMemoRequired(transaction);
    }
    const tx = encodeURIComponent(
      transaction.toEnvelope().toXDR().toString("base64")
    );
    const url = new URL(this.serverURL);
    url.pathname = url.pathname.split("/").concat(["transactions"]).filter((value) => value.length > 0).join("/");
    return this.httpClient.post(url.toString(), `tx=${tx}`, {
      timeout: SUBMIT_TRANSACTION_TIMEOUT,
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    }).then((response) => {
      if (!response.data.result_xdr) {
        return response.data;
      }
      const responseXDR = types.TransactionResult.fromXDR(
        response.data.result_xdr,
        "base64"
      );
      const results = responseXDR.result().value();
      let offerResults;
      let hasManageOffer;
      if (results.length) {
        offerResults = results.map((result, i) => {
          if (result.value().switch().name !== "manageBuyOffer" && result.value().switch().name !== "manageSellOffer") {
            return null;
          }
          hasManageOffer = true;
          let amountBought = new BigNumber(0);
          let amountSold = new BigNumber(0);
          const offerSuccess = result.value().value().success();
          const offersClaimed = offerSuccess.offersClaimed().map((offerClaimedAtom) => {
            const offerClaimed = offerClaimedAtom.value();
            let sellerId = "";
            switch (offerClaimedAtom.switch()) {
              case types.ClaimAtomType.claimAtomTypeV0():
                sellerId = StrKey.encodeEd25519PublicKey(
                  offerClaimed.sellerEd25519()
                );
                break;
              case types.ClaimAtomType.claimAtomTypeOrderBook():
                sellerId = StrKey.encodeEd25519PublicKey(
                  offerClaimed.sellerId().ed25519()
                );
                break;
              // It shouldn't be possible for a claimed offer to have type
              // claimAtomTypeLiquidityPool:
              //
              // https://github.com/stellar/stellar-core/blob/c5f6349b240818f716617ca6e0f08d295a6fad9a/src/transactions/TransactionUtils.cpp#L1284
              //
              // However, you can never be too careful.
              default:
                throw new Error(
                  `Invalid offer result type: ${offerClaimedAtom.switch()}`
                );
            }
            const claimedOfferAmountBought = new BigNumber(
              // amountBought is a js-xdr hyper
              offerClaimed.amountBought().toString()
            );
            const claimedOfferAmountSold = new BigNumber(
              // amountBought is a js-xdr hyper
              offerClaimed.amountSold().toString()
            );
            amountBought = amountBought.plus(claimedOfferAmountSold);
            amountSold = amountSold.plus(claimedOfferAmountBought);
            const sold = Asset.fromOperation(offerClaimed.assetSold());
            const bought = Asset.fromOperation(
              offerClaimed.assetBought()
            );
            const assetSold = {
              type: sold.getAssetType(),
              assetCode: sold.getCode(),
              issuer: sold.getIssuer()
            };
            const assetBought = {
              type: bought.getAssetType(),
              assetCode: bought.getCode(),
              issuer: bought.getIssuer()
            };
            return {
              sellerId,
              offerId: offerClaimed.offerId().toString(),
              assetSold,
              amountSold: getAmountInLumens(claimedOfferAmountSold),
              assetBought,
              amountBought: getAmountInLumens(claimedOfferAmountBought)
            };
          });
          const effect = offerSuccess.offer().switch().name;
          let currentOffer;
          if (typeof offerSuccess.offer().value === "function" && offerSuccess.offer().value()) {
            const offerXDR = offerSuccess.offer().value();
            currentOffer = {
              offerId: offerXDR.offerId().toString(),
              selling: {},
              buying: {},
              amount: getAmountInLumens(offerXDR.amount().toString()),
              price: {
                n: offerXDR.price().n(),
                d: offerXDR.price().d()
              }
            };
            const selling = Asset.fromOperation(offerXDR.selling());
            currentOffer.selling = {
              type: selling.getAssetType(),
              assetCode: selling.getCode(),
              issuer: selling.getIssuer()
            };
            const buying = Asset.fromOperation(offerXDR.buying());
            currentOffer.buying = {
              type: buying.getAssetType(),
              assetCode: buying.getCode(),
              issuer: buying.getIssuer()
            };
          }
          return {
            offersClaimed,
            effect,
            operationIndex: i,
            currentOffer,
            // this value is in stroops so divide it out
            amountBought: getAmountInLumens(amountBought),
            amountSold: getAmountInLumens(amountSold),
            isFullyOpen: !offersClaimed.length && effect !== "manageOfferDeleted",
            wasPartiallyFilled: !!offersClaimed.length && effect !== "manageOfferDeleted",
            wasImmediatelyFilled: !!offersClaimed.length && effect === "manageOfferDeleted",
            wasImmediatelyDeleted: !offersClaimed.length && effect === "manageOfferDeleted"
          };
        }).filter((result) => !!result);
      }
      return {
        ...response.data,
        offerResults: hasManageOffer ? offerResults : void 0
      };
    }).catch((response) => {
      if (response instanceof Error) {
        return Promise.reject(response);
      }
      return Promise.reject(
        new BadResponseError(
          `Transaction submission failed. Server responded: ${response.status} ${response.statusText}`,
          response.data
        )
      );
    });
  }
  /**
   * Submits an asynchronous transaction to the network. Unlike the synchronous version, which blocks
   * and waits for the transaction to be ingested in Horizon, this endpoint relays the response from
   * core directly back to the user.
   *
   * By default, this function calls {@link HorizonServer.checkMemoRequired}, you can
   * skip this check by setting the option `skipMemoRequiredCheck` to `true`.
   *
   * @see [Submit-Async-Transaction](https://developers.stellar.org/docs/data/horizon/api-reference/resources/submit-async-transaction)
   * @param transaction - The transaction to submit.
   * @param opts - (optional) Options object
   *   - `skipMemoRequiredCheck` (optional): Allow skipping memo
   * required check, default: `false`. See
   * [SEP0029](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0029.md).
   * @returns Promise that resolves or rejects with response from
   * horizon.
   */
  async submitAsyncTransaction(transaction, opts = {
    skipMemoRequiredCheck: false
  }) {
    if (!opts.skipMemoRequiredCheck) {
      await this.checkMemoRequired(transaction);
    }
    const tx = encodeURIComponent(
      transaction.toEnvelope().toXDR().toString("base64")
    );
    const url = new URL(this.serverURL);
    url.pathname = url.pathname.split("/").concat(["transactions_async"]).filter((value) => value.length > 0).join("/");
    return this.httpClient.post(url.toString(), `tx=${tx}`, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    }).then((response) => response.data).catch((response) => {
      if (response instanceof Error) {
        return Promise.reject(response);
      }
      return Promise.reject(
        new BadResponseError(
          `Transaction submission failed. Server responded: ${response.status} ${response.statusText}`,
          response.data
        )
      );
    });
  }
  /**
   * @returns New {@link AccountCallBuilder} object configured by a current Horizon server configuration.
   */
  accounts() {
    return new AccountCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link ClaimableBalanceCallBuilder} object configured by a current Horizon server configuration.
   */
  claimableBalances() {
    return new ClaimableBalanceCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link LedgerCallBuilder} object configured by a current Horizon server configuration.
   */
  ledgers() {
    return new LedgerCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link TransactionCallBuilder} object configured by a current Horizon server configuration.
   */
  transactions() {
    return new TransactionCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * People on the Stellar network can make offers to buy or sell assets. This endpoint represents all the offers on the DEX.
   *
   * You can query all offers for account using the function `.accountId`.
   *
   * @example
   * ```ts
   * server.offers()
   *   .forAccount(accountId).call()
   *   .then(function(offers) {
   *     console.log(offers);
   *   });
   * ```
   *
   * @returns New {@link OfferCallBuilder} object
   */
  offers() {
    return new OfferCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @param selling - Asset being sold
   * @param buying - Asset being bought
   * @returns New {@link OrderbookCallBuilder} object configured by a current Horizon server configuration.
   */
  orderbook(selling, buying) {
    return new OrderbookCallBuilder(
      this.serverURL,
      this.httpClient,
      selling,
      buying
    );
  }
  /**
   * Returns
   * @returns New {@link TradesCallBuilder} object configured by a current Horizon server configuration.
   */
  trades() {
    return new TradesCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link OperationCallBuilder} object configured by a current Horizon server configuration.
   */
  operations() {
    return new OperationCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link LiquidityPoolCallBuilder}
   *     object configured to the current Horizon server settings.
   */
  liquidityPools() {
    return new LiquidityPoolCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * The Stellar Network allows payments to be made between assets through path
   * payments. A strict receive path payment specifies a series of assets to
   * route a payment through, from source asset (the asset debited from the
   * payer) to destination asset (the asset credited to the payee).
   *
   * A strict receive path search is specified using:
   *
   * * The destination address.
   * * The source address or source assets.
   * * The asset and amount that the destination account should receive.
   *
   * As part of the search, horizon will load a list of assets available to the
   * source address and will find any payment paths from those source assets to
   * the desired destination asset. The search's amount parameter will be used
   * to determine if there a given path can satisfy a payment of the desired
   * amount.
   *
   * If a list of assets is passed as the source, horizon will find any payment
   * paths from those source assets to the desired destination asset.
   *
   * @param source - The sender's account ID or a list of assets. Any returned path will use a source that the sender can hold.
   * @param destinationAsset - The destination asset.
   * @param destinationAmount - The amount, denominated in the destination asset, that any returned path should be able to satisfy.
   * @returns New {@link StrictReceivePathCallBuilder} object configured with the current Horizon server configuration.
   */
  strictReceivePaths(source, destinationAsset, destinationAmount) {
    return new StrictReceivePathCallBuilder(
      this.serverURL,
      this.httpClient,
      source,
      destinationAsset,
      destinationAmount
    );
  }
  /**
   * The Stellar Network allows payments to be made between assets through path payments. A strict send path payment specifies a
   * series of assets to route a payment through, from source asset (the asset debited from the payer) to destination
   * asset (the asset credited to the payee).
   *
   * A strict send path search is specified using:
   *
   * The asset and amount that is being sent.
   * The destination account or the destination assets.
   *
   * @param sourceAsset - The asset to be sent.
   * @param sourceAmount - The amount, denominated in the source asset, that any returned path should be able to satisfy.
   * @param destination - The destination account or the destination assets.
   * @returns New {@link StrictSendPathCallBuilder} object configured with the current Horizon server configuration.
   */
  strictSendPaths(sourceAsset, sourceAmount, destination) {
    return new StrictSendPathCallBuilder(
      this.serverURL,
      this.httpClient,
      sourceAsset,
      sourceAmount,
      destination
    );
  }
  /**
   * @returns New {@link PaymentCallBuilder} instance configured with the current
   * Horizon server configuration.
   */
  payments() {
    return new PaymentCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @returns New {@link EffectCallBuilder} instance configured with the current
   * Horizon server configuration
   */
  effects() {
    return new EffectCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * @param address - The Stellar ID that you want Friendbot to send lumens to
   * @returns New {@link FriendbotBuilder} instance configured with the current
   * Horizon server configuration
   */
  friendbot(address) {
    return new FriendbotBuilder(this.serverURL, this.httpClient, address);
  }
  /**
   * Get a new {@link AssetsCallBuilder} instance configured with the current
   * Horizon server configuration.
   * @returns New AssetsCallBuilder instance
   */
  assets() {
    return new AssetsCallBuilder(this.serverURL, this.httpClient);
  }
  /**
   * Fetches an account's most current state in the ledger, then creates and
   * returns an {@link AccountResponse} object.
   *
   * @param accountId - The account to load.
   *
   * @returns Returns a promise to the {@link AccountResponse} object
   * with populated sequence number.
   */
  async loadAccount(accountId) {
    const res = await this.accounts().accountId(accountId).call();
    return new AccountResponse(res);
  }
  /**
   *
   * @param base - base asset
   * @param counter - counter asset
   * @param start_time - lower time boundary represented as millis since epoch
   * @param end_time - upper time boundary represented as millis since epoch
   * @param resolution - segment duration as millis since epoch. *Supported values are 5 minutes (300000), 15 minutes (900000), 1 hour (3600000), 1 day (86400000) and 1 week (604800000).
   * @param offset - segments can be offset using this parameter. Expressed in milliseconds. *Can only be used if the resolution is greater than 1 hour. Value must be in whole hours, less than the provided resolution, and less than 24 hours.
   * Returns new {@link TradeAggregationCallBuilder} object configured with the current Horizon server configuration.
   * @returns New TradeAggregationCallBuilder instance
   */
  tradeAggregation(base, counter, start_time, end_time, resolution, offset) {
    return new TradeAggregationCallBuilder(
      this.serverURL,
      this.httpClient,
      base,
      counter,
      start_time,
      end_time,
      resolution,
      offset
    );
  }
  /**
   * Check if any of the destination accounts requires a memo.
   *
   * This function implements a memo required check as defined in
   * [SEP-29](https://stellar.org/protocol/sep-29). It will load each account
   * which is the destination and check if it has the data field
   * `config.memo_required` set to `"MQ=="`.
   *
   * Each account is checked sequentially instead of loading multiple accounts
   * at the same time from Horizon.
   *
   * @see {@link https://stellar.org/protocol/sep-29 | SEP-29: Account Memo Requirements}
   * @param transaction - The transaction to check.
   * @returns - If any of the destination account
   * requires a memo, the promise will throw {@link AccountRequiresMemoError}.
   * @throws    */
  async checkMemoRequired(transaction) {
    if (transaction instanceof FeeBumpTransaction) {
      transaction = transaction.innerTransaction;
    }
    if (transaction.memo.type !== "none") {
      return;
    }
    const destinations = /* @__PURE__ */ new Set();
    for (let i = 0; i < transaction.operations.length; i += 1) {
      const operation = transaction.operations[i];
      switch (operation.type) {
        case "payment":
        case "pathPaymentStrictReceive":
        case "pathPaymentStrictSend":
        case "accountMerge":
          break;
        default:
          continue;
      }
      const destination = operation.destination;
      if (destinations.has(destination)) {
        continue;
      }
      destinations.add(destination);
      if (destination.startsWith("M")) {
        continue;
      }
      try {
        const account = await this.loadAccount(destination);
        if (account.data_attr["config.memo_required"] === ACCOUNT_REQUIRES_MEMO) {
          throw new AccountRequiresMemoError(
            "account requires memo",
            destination,
            i
          );
        }
      } catch (e) {
        if (e instanceof AccountRequiresMemoError) {
          throw e;
        }
        if (!(e instanceof NotFoundError)) {
          throw e;
        }
        continue;
      }
    }
  }
}

export { HorizonServer, SUBMIT_TRANSACTION_TIMEOUT };
//# sourceMappingURL=server.js.map
