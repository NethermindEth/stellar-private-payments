'use strict';

var smolToml = require('smol-toml');
var config = require('../config.js');
var fetchClient = require('../http-client/fetch-client.js');

const STELLAR_TOML_MAX_SIZE = 100 * 1024;
class Resolver {
  /**
   * Returns a parsed `stellar.toml` file for a given domain.
   * @see {@link https://developers.stellar.org/docs/tokens/publishing-asset-info | Stellar.toml doc}
   *
   * @param domain - Domain to get stellar.toml file for
   * @param opts - (optional) Options object
   *   - `allowHttp` (optional): Allow connecting to http servers. This must be set to false in production deployments!
   *   - `timeout` (optional): Allow a timeout. Allows user to avoid nasty lag due to TOML resolve issue.
   * @returns A `Promise` that resolves to the parsed stellar.toml object
   *
   * @example
   * ```ts
   * StellarSdk.StellarToml.Resolver.resolve('acme.com')
   *   .then(stellarToml => {
   *     // stellarToml in an object representing domain stellar.toml file.
   *   })
   *   .catch(error => {
   *     // stellar.toml does not exist or is invalid
   *   });
   * ```
   */
  static async resolve(domain, opts = {}) {
    const { CancelToken } = fetchClient.fetchClient;
    const allowHttp = typeof opts.allowHttp === "undefined" ? config.Config.isAllowHttp() : opts.allowHttp;
    const timeout = typeof opts.timeout === "undefined" ? config.Config.getTimeout() : opts.timeout;
    const protocol = allowHttp ? "http" : "https";
    return fetchClient.fetchClient.get(`${protocol}://${domain}/.well-known/stellar.toml`, {
      maxRedirects: opts.allowedRedirects ?? 0,
      maxContentLength: STELLAR_TOML_MAX_SIZE,
      cancelToken: timeout ? new CancelToken(
        (cancel) => setTimeout(
          () => cancel(`timeout of ${timeout}ms exceeded`),
          timeout
        )
      ) : void 0,
      timeout
    }).then((response) => {
      try {
        const tomlObject = smolToml.parse(response.data);
        return Promise.resolve(tomlObject);
      } catch (e) {
        return Promise.reject(
          new Error(
            `stellar.toml is invalid - Parsing error on line ${e.line}, column ${e.column}: ${e.message}`
          )
        );
      }
    }).catch((err) => {
      if (err.message.match(/^maxContentLength size/)) {
        throw new Error(
          `stellar.toml file exceeds allowed size of ${STELLAR_TOML_MAX_SIZE}`
        );
      } else {
        throw err;
      }
    });
  }
}

exports.Resolver = Resolver;
exports.STELLAR_TOML_MAX_SIZE = STELLAR_TOML_MAX_SIZE;
//# sourceMappingURL=index.js.map
