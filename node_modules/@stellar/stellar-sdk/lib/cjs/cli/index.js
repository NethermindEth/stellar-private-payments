'use strict';

var commander = require('commander');
var path = require('path');
var wasm_fetcher = require('../bindings/wasm_fetcher.js');
var util = require('./util.js');
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
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
require('../base/muxed_account.js');
var network = require('../base/network.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');

function _interopNamespace(e) {
  if (e && e.__esModule) return e;
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var path__namespace = /*#__PURE__*/_interopNamespace(path);

const NETWORK_CONFIG = {
  testnet: {
    passphrase: network.Networks.TESTNET,
    rpcUrl: "https://soroban-testnet.stellar.org"
  },
  mainnet: {
    passphrase: network.Networks.PUBLIC,
    rpcUrl: null
    // User must provide their own
  },
  futurenet: {
    passphrase: network.Networks.FUTURENET,
    rpcUrl: "https://rpc-futurenet.stellar.org"
  },
  localnet: {
    passphrase: network.Networks.STANDALONE,
    rpcUrl: "http://localhost:8000/rpc"
  }
};
function runCli() {
  const program = new commander.Command();
  program.name("stellar-cli").description("CLI for generating TypeScript bindings for Stellar contracts").version("1.0.0");
  program.command("generate").description("Generate TypeScript bindings for a Stellar contract").helpOption("-h, --help", "Display help for command").option("--wasm <path>", "Path to local WASM file").option("--wasm-hash <hash>", "Hash of WASM blob on network").option("--contract-id <id>", "Contract ID on network").option("--rpc-url <url>", "RPC server URL").option(
    "--network <network>",
    "Network options to use: mainnet, testnet, futurenet, or localnet"
  ).option("--output-dir <dir>", "Output directory for generated bindings").option(
    "--allow-http",
    "Allow insecure HTTP connections to RPC server",
    false
  ).option("--timeout <ms>", "RPC request timeout in milliseconds").option(
    "--headers <json>",
    `Custom headers as JSON object (e.g., '{"Authorization": "Bearer token"}')`
  ).option(
    "--contract-name <name>",
    "Name for the generated contract client class"
  ).option("--overwrite", "Overwrite existing files", false).action(async (options) => {
    try {
      let networkPassphrase;
      let rpcUrl = options.rpcUrl;
      let allowHttp = options.allowHttp;
      if (options.network) {
        const network = options.network.toLowerCase();
        const config = NETWORK_CONFIG[network];
        if (!config) {
          throw new Error(
            `
\u2717 Invalid network: ${options.network}. Must be mainnet, testnet, futurenet, or localnet`
          );
        }
        networkPassphrase = config.passphrase;
        const needsRpcUrl = options.wasmHash || options.contractId;
        if (!rpcUrl && needsRpcUrl) {
          if (config.rpcUrl) {
            rpcUrl = config.rpcUrl;
            console.log(`Using default RPC URL for ${network}: ${rpcUrl}`);
            if (network === "localnet" && !options.allowHttp) {
              allowHttp = true;
            }
          } else if (network === "mainnet") {
            throw new Error(
              `
\u2717 --rpc-url is required for mainnet. Find RPC providers at: https://developers.stellar.org/docs/data/rpc/rpc-providers`
            );
          }
        }
      }
      if (options.outputDir === void 0) {
        throw new Error("Output directory (--output-dir) is required");
      }
      let headers;
      if (options.headers) {
        try {
          headers = JSON.parse(options.headers);
        } catch {
          throw new Error(`Invalid JSON for --headers: ${options.headers}`);
        }
      }
      let timeout;
      if (options.timeout) {
        timeout = parseInt(options.timeout, 10);
        if (Number.isNaN(timeout) || timeout <= 0) {
          throw new Error(
            `Invalid timeout value: ${options.timeout}. Must be a positive integer.`
          );
        }
      }
      console.log("Fetching contract...");
      const { generator, source } = await util.createGenerator({
        wasm: options.wasm,
        wasmHash: options.wasmHash,
        contractId: options.contractId,
        rpcUrl,
        networkPassphrase,
        serverOptions: { allowHttp, timeout, headers }
      });
      util.logSourceInfo(source);
      const contractName = options.contractName || util.deriveContractName(source) || "contract";
      console.log(
        `
\u2713 Generating TypeScript bindings for "${contractName}"...`
      );
      await util.generateAndWrite(generator, {
        contractName,
        outputDir: path__namespace.resolve(options.outputDir),
        overwrite: options.overwrite
      });
      console.log(
        `
\u2713 Successfully generated bindings in ${options.outputDir}`
      );
      console.log(`
Usage:`);
      console.log(
        `  import { Client } from './${path__namespace.basename(options.outputDir)}';`
      );
    } catch (error) {
      if (error instanceof wasm_fetcher.WasmFetchError) {
        console.error(`
\u2717 Error: ${error.message}`);
        if (error.cause) {
          console.error(`  Caused by: ${error.cause.message}`);
        }
      } else if (error instanceof Error) {
        console.error(`
\u2717 Error: ${error.message}`);
      } else {
        console.error(`
\u2717 Unexpected error:`, error);
      }
      process.exit(1);
    }
  });
  program.parse();
}

exports.runCli = runCli;
//# sourceMappingURL=index.js.map
