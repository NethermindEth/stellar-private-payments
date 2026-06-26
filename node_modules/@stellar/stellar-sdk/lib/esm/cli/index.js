import { Command } from 'commander';
import * as path from 'path';
import { WasmFetchError } from '../bindings/wasm_fetcher.js';
import { createGenerator, logSourceInfo, deriveContractName, generateAndWrite } from './util.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import '../base/muxed_account.js';
import { Networks } from '../base/network.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';

const NETWORK_CONFIG = {
  testnet: {
    passphrase: Networks.TESTNET,
    rpcUrl: "https://soroban-testnet.stellar.org"
  },
  mainnet: {
    passphrase: Networks.PUBLIC,
    rpcUrl: null
    // User must provide their own
  },
  futurenet: {
    passphrase: Networks.FUTURENET,
    rpcUrl: "https://rpc-futurenet.stellar.org"
  },
  localnet: {
    passphrase: Networks.STANDALONE,
    rpcUrl: "http://localhost:8000/rpc"
  }
};
function runCli() {
  const program = new Command();
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
      const { generator, source } = await createGenerator({
        wasm: options.wasm,
        wasmHash: options.wasmHash,
        contractId: options.contractId,
        rpcUrl,
        networkPassphrase,
        serverOptions: { allowHttp, timeout, headers }
      });
      logSourceInfo(source);
      const contractName = options.contractName || deriveContractName(source) || "contract";
      console.log(
        `
\u2713 Generating TypeScript bindings for "${contractName}"...`
      );
      await generateAndWrite(generator, {
        contractName,
        outputDir: path.resolve(options.outputDir),
        overwrite: options.overwrite
      });
      console.log(
        `
\u2713 Successfully generated bindings in ${options.outputDir}`
      );
      console.log(`
Usage:`);
      console.log(
        `  import { Client } from './${path.basename(options.outputDir)}';`
      );
    } catch (error) {
      if (error instanceof WasmFetchError) {
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

export { runCli };
//# sourceMappingURL=index.js.map
