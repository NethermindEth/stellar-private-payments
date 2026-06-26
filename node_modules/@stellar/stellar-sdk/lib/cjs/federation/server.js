'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
require('../base/generated/curr_generated.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
var strkey = require('../base/strkey.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var config = require('../config.js');
var bad_response = require('../errors/bad_response.js');
var index = require('../stellartoml/index.js');
var utils = require('./utils.js');
var fetchClient = require('../http-client/fetch-client.js');

const FEDERATION_RESPONSE_MAX_SIZE = 100 * 1024;
class FederationServer {
  /**
   * The federation server URL (ex. `https://acme.com/federation`).
   */
  serverURL;
  // TODO: public or private? readonly?
  /**
   * Domain this server represents.
   */
  domain;
  // TODO: public or private? readonly?
  /**
   * Allow a timeout, default: 0. Allows user to avoid nasty lag due to TOML resolve issue.
   */
  timeout;
  // TODO: public or private? readonly?
  /**
   * A helper method for handling user inputs that contain `destination` value.
   * It accepts two types of values:
   *
   * * For Stellar address (ex. `bob*stellar.org`) it splits Stellar address and then tries to find information about
   * federation server in `stellar.toml` file for a given domain. It returns a `Promise` which resolves if federation
   * server exists and user has been found and rejects in all other cases.
   * * For Account ID (ex. `GB5XVAABEQMY63WTHDQ5RXADGYF345VWMNPTN2GFUDZT57D57ZQTJ7PS`) it returns a `Promise` which
   * resolves if Account ID is valid and rejects in all other cases. Please note that this method does not check
   * if the account actually exists in a ledger.
   *
   * @example
   * ```ts
   * StellarSdk.FederationServer.resolve('bob*stellar.org')
   *  .then(federationRecord => {
   *    // {
   *    //   account_id: 'GB5XVAABEQMY63WTHDQ5RXADGYF345VWMNPTN2GFUDZT57D57ZQTJ7PS',
   *    //   memo_type: 'id',
   *    //   memo: 100
   *    // }
   *  });
   * ```
   *
   * @see <a href="https://developers.stellar.org/docs/learn/encyclopedia/federation" target="_blank">Federation doc</a>
   * @see <a href="https://developers.stellar.org/docs/issuing-assets/publishing-asset-info" target="_blank">Stellar.toml doc</a>
   * @param value - Stellar Address (ex. `bob*stellar.org`)
   * @param opts - (optional) Options object
   * @returns A promise that resolves to the federation record
   * @throws Will throw an error if the provided account ID is not a valid Ed25519 public key.
   */
  static async resolve(value, opts = {}) {
    if (value.indexOf("*") < 0) {
      if (!strkey.StrKey.isValidEd25519PublicKey(value)) {
        return Promise.reject(new Error("Invalid Account ID"));
      }
      return Promise.resolve({ account_id: value });
    }
    const addressParts = value.split("*");
    const [, domain] = addressParts;
    if (addressParts.length !== 2 || !domain) {
      return Promise.reject(new Error("Invalid Stellar address"));
    }
    const federationServer = await FederationServer.createForDomain(
      domain,
      opts
    );
    return federationServer.resolveAddress(value);
  }
  /**
   * Creates a `FederationServer` instance based on information from
   * [stellar.toml](https://developers.stellar.org/docs/issuing-assets/publishing-asset-info)
   * file for a given domain.
   *
   * If `stellar.toml` file does not exist for a given domain or it does not
   * contain information about a federation server Promise will reject.
   *
   * @example
   * ```ts
   * StellarSdk.FederationServer.createForDomain('acme.com')
   *   .then(federationServer => {
   *     // federationServer.resolveAddress('bob').then(...)
   *   })
   *   .catch(error => {
   *     // stellar.toml does not exist or it does not contain information about federation server.
   *   });
   * ```
   *
   * @see <a href="https://developers.stellar.org/docs/issuing-assets/publishing-asset-info" target="_blank">Stellar.toml doc</a>
   * @param domain - Domain to get federation server for
   * @param opts - (optional) Options object
   * @returns A promise that resolves to the federation record
   * @throws Will throw an error if the domain's stellar.toml file does not contain a federation server field.
   */
  static async createForDomain(domain, opts = {}) {
    utils.validateDomain(domain);
    const tomlObject = await index.Resolver.resolve(domain, opts);
    if (!tomlObject.FEDERATION_SERVER) {
      return Promise.reject(
        new Error("stellar.toml does not contain FEDERATION_SERVER field")
      );
    }
    return new FederationServer(tomlObject.FEDERATION_SERVER, domain, opts);
  }
  constructor(serverURL, domain, opts = {}) {
    this.serverURL = new URL(serverURL);
    this.domain = domain;
    utils.validateDomain(domain);
    const allowHttp = typeof opts.allowHttp === "undefined" ? config.Config.isAllowHttp() : opts.allowHttp;
    this.timeout = typeof opts.timeout === "undefined" ? config.Config.getTimeout() : opts.timeout;
    if (this.serverURL.protocol !== "https:" && !allowHttp) {
      throw new Error("Cannot connect to insecure federation server");
    }
  }
  /**
   * Get the federation record if the user was found for a given Stellar address
   * @see <a href="https://developers.stellar.org/docs/encyclopedia/federation" target="_blank">Federation doc</a>
   * @param address - Stellar address (ex. `bob*stellar.org`). If `FederationServer` was instantiated with `domain` param only username (ex. `bob`) can be passed.
   * @returns A promise that resolves to the federation record
   * @throws Will throw an error if the federated address does not contain a domain, or if the server object was not instantiated with a `domain` parameter
   */
  async resolveAddress(address) {
    let stellarAddress = address;
    if (address.indexOf("*") < 0) {
      if (!this.domain) {
        return Promise.reject(
          new Error(
            "Unknown domain. Make sure `address` contains a domain (ex. `bob*stellar.org`) or pass `domain` parameter when instantiating the server object."
          )
        );
      }
      stellarAddress = `${address}*${this.domain}`;
    }
    const url = new URL(this.serverURL);
    url.search = "";
    url.searchParams.set("type", "name");
    url.searchParams.set("q", stellarAddress);
    return this._sendRequest(url);
  }
  /**
   * Given an account ID, get their federation record if the user was found
   * @see <a href="https://developers.stellar.org/docs/encyclopedia/federation" target="_blank">Federation doc</a>
   * @param accountId - Account ID (ex. `GBYNR2QJXLBCBTRN44MRORCMI4YO7FZPFBCNOKTOBCAAFC7KC3LNPRYS`)
   * @returns A promise that resolves to the federation record
   * @throws Will throw an error if the federation server returns an invalid memo value.
   * @throws Will throw an error if the federation server's response exceeds the allowed maximum size.
   * @throws Will throw an error if the server query fails with an improper response.
   */
  async resolveAccountId(accountId) {
    const url = new URL(this.serverURL);
    url.search = "";
    url.searchParams.set("type", "id");
    url.searchParams.set("q", accountId);
    return this._sendRequest(url);
  }
  /**
   * Given a transactionId, get the federation record if the sender of the transaction was found
   * @see <a href="https://developers.stellar.org/docs/glossary/federation/" target="_blank">Federation doc</a>
   * @param transactionId - Transaction ID (ex. `3389e9f0f1a65f19736cacf544c2e825313e8447f569233bb8db39aa607c8889`)
   * @returns A promise that resolves to the federation record
   * @throws Will throw an error if the federation server returns an invalid memo value.
   * @throws Will throw an error if the federation server's response exceeds the allowed maximum size.
   * @throws Will throw an error if the server query fails with an improper response.
   */
  async resolveTransactionId(transactionId) {
    const url = new URL(this.serverURL);
    url.search = "";
    url.searchParams.set("type", "txid");
    url.searchParams.set("q", transactionId);
    return this._sendRequest(url);
  }
  async _sendRequest(url) {
    const timeout = this.timeout;
    return fetchClient.fetchClient.get(url.toString(), {
      maxContentLength: FEDERATION_RESPONSE_MAX_SIZE,
      timeout
    }).then((response) => {
      if (typeof response.data.memo !== "undefined" && typeof response.data.memo !== "string") {
        throw new Error("memo value should be of type string");
      }
      return response.data;
    }).catch((response) => {
      if (response instanceof Error) {
        if (response.message.match(/^maxContentLength size/)) {
          throw new Error(
            `federation response exceeds allowed size of ${FEDERATION_RESPONSE_MAX_SIZE}`
          );
        } else {
          return Promise.reject(response);
        }
      } else {
        return Promise.reject(
          new bad_response.BadResponseError(
            `Server query failed. Server responded: ${response.status} ${response.statusText}`,
            response.data
          )
        );
      }
    });
  }
}

exports.FEDERATION_RESPONSE_MAX_SIZE = FEDERATION_RESPONSE_MAX_SIZE;
exports.FederationServer = FederationServer;
//# sourceMappingURL=server.js.map
