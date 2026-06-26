'use strict';

var fs = require('fs/promises');
var path = require('path');
var generator = require('../bindings/generator.js');
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
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var wasm_fetcher = require('../bindings/wasm_fetcher.js');
var server = require('../rpc/server.js');

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

var fs__namespace = /*#__PURE__*/_interopNamespace(fs);
var path__namespace = /*#__PURE__*/_interopNamespace(path);

async function verifyNetwork(server, expectedPassphrase) {
  const networkResponse = await server.getNetwork();
  if (networkResponse.passphrase !== expectedPassphrase) {
    throw new wasm_fetcher.WasmFetchError(
      `Network mismatch: expected "${expectedPassphrase}", got "${networkResponse.passphrase}"`
    );
  }
}
async function createGenerator(args) {
  const sources = [args.wasm, args.wasmHash, args.contractId].filter(Boolean);
  if (sources.length === 0) {
    throw new wasm_fetcher.WasmFetchError(
      "Must provide one of: --wasm, --wasm-hash, or --contract-id"
    );
  }
  if (sources.length > 1) {
    throw new wasm_fetcher.WasmFetchError(
      "Must provide only one of: --wasm, --wasm-hash, or --contract-id"
    );
  }
  if (args.wasm) {
    const wasmBuffer = await fs__namespace.readFile(args.wasm);
    return {
      generator: generator.BindingGenerator.fromWasm(wasmBuffer),
      source: { type: "file", path: args.wasm }
    };
  }
  if (!args.rpcUrl) {
    throw new wasm_fetcher.WasmFetchError(
      "--rpc-url is required when fetching from network"
    );
  }
  if (!args.networkPassphrase) {
    throw new wasm_fetcher.WasmFetchError(
      "--network is required when fetching from network"
    );
  }
  const server$1 = new server.RpcServer(args.rpcUrl, args.serverOptions);
  await verifyNetwork(server$1, args.networkPassphrase);
  if (args.wasmHash) {
    return {
      generator: await generator.BindingGenerator.fromWasmHash(args.wasmHash, server$1),
      source: {
        type: "wasm-hash",
        hash: args.wasmHash,
        rpcUrl: args.rpcUrl,
        network: args.networkPassphrase
      }
    };
  }
  if (args.contractId) {
    const generator$1 = await generator.BindingGenerator.fromContractId(
      args.contractId,
      server$1
    );
    return {
      generator: generator$1,
      source: {
        type: "contract-id",
        contractId: args.contractId,
        rpcUrl: args.rpcUrl,
        network: args.networkPassphrase
      }
    };
  }
  throw new wasm_fetcher.WasmFetchError("Invalid arguments");
}
async function writeBindings(outputDir, bindings, overwrite) {
  try {
    const stat = await fs__namespace.stat(outputDir);
    if (stat.isFile()) {
      throw new Error(`Output path is a file: ${outputDir}`);
    }
    if (!overwrite) {
      throw new Error(`Directory exists (use --overwrite): ${outputDir}`);
    }
    await fs__namespace.rm(outputDir, { recursive: true, force: true });
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  await fs__namespace.mkdir(path__namespace.join(outputDir, "src"), { recursive: true });
  const writes = [
    fs__namespace.writeFile(path__namespace.join(outputDir, "src/index.ts"), bindings.index),
    fs__namespace.writeFile(path__namespace.join(outputDir, "src/client.ts"), bindings.client),
    fs__namespace.writeFile(path__namespace.join(outputDir, ".gitignore"), bindings.gitignore),
    fs__namespace.writeFile(path__namespace.join(outputDir, "README.md"), bindings.readme),
    fs__namespace.writeFile(path__namespace.join(outputDir, "package.json"), bindings.packageJson),
    fs__namespace.writeFile(path__namespace.join(outputDir, "tsconfig.json"), bindings.tsConfig)
  ];
  if (bindings.types.trim()) {
    writes.push(
      fs__namespace.writeFile(path__namespace.join(outputDir, "src/types.ts"), bindings.types)
    );
  }
  await Promise.all(writes);
}
async function generateAndWrite(generator, options) {
  const { outputDir, overwrite = false, ...genOptions } = options;
  const bindings = generator.generate(genOptions);
  await writeBindings(outputDir, bindings, overwrite);
}
function logSourceInfo(source) {
  console.log("\nSource:");
  switch (source.type) {
    case "file":
      console.log(`  Type: Local file`);
      console.log(`  Path: ${source.path}`);
      break;
    case "wasm-hash":
      console.log(`  Type: WASM hash`);
      console.log(`  Hash: ${source.hash}`);
      console.log(`  RPC: ${source.rpcUrl}`);
      console.log(`  Network: ${source.network}`);
      break;
    case "contract-id":
      console.log(`  Type: Contract ID`);
      console.log(`  Address: ${source.contractId}`);
      console.log(`  RPC: ${source.rpcUrl}`);
      console.log(`  Network: ${source.network}`);
      break;
  }
}
function deriveContractName(source) {
  if (source.type !== "file") return null;
  return path__namespace.basename(source.path, path__namespace.extname(source.path)).replace(/([a-z])([A-Z])/g, "$1-$2").replace(/_/g, "-").toLowerCase();
}

exports.createGenerator = createGenerator;
exports.deriveContractName = deriveContractName;
exports.generateAndWrite = generateAndWrite;
exports.logSourceInfo = logSourceInfo;
exports.writeBindings = writeBindings;
//# sourceMappingURL=util.js.map
