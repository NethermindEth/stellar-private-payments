'use strict';

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var curr_generated = require('../base/generated/curr_generated.js');
var jsxdr = require('../base/jsxdr.js');
require('@noble/hashes/sha2.js');
require('../base/signing.js');
require('../base/keypair.js');
require('base32.js');
require('../base/util/continued_fraction.js');
require('../base/util/bignumber.js');
require('../base/transaction_builder.js');
var account = require('../base/account.js');
require('../base/muxed_account.js');
require('../base/scval.js');
require('../base/numbers/uint128.js');
require('../base/numbers/uint256.js');
require('../base/numbers/int128.js');
require('../base/numbers/int256.js');
var types = require('./types.js');

async function withExponentialBackoff(fn, keepWaitingIf, timeoutInSeconds, exponentialFactor = 1.5, verbose = false) {
  const attempts = [];
  let count = 0;
  attempts.push(await fn());
  if (!keepWaitingIf(attempts[attempts.length - 1])) return attempts;
  const waitUntil = new Date(Date.now() + timeoutInSeconds * 1e3).valueOf();
  let waitTime = 1e3;
  let totalWaitTime = waitTime;
  while (Date.now() < waitUntil && keepWaitingIf(attempts[attempts.length - 1])) {
    count += 1;
    if (verbose) {
      console.info(
        `Waiting ${waitTime}ms before trying again (bringing the total wait time to ${totalWaitTime}ms so far, of total ${timeoutInSeconds * 1e3}ms)`
      );
    }
    await new Promise((res) => setTimeout(res, waitTime));
    waitTime *= exponentialFactor;
    if (new Date(Date.now() + waitTime).valueOf() > waitUntil) {
      waitTime = waitUntil - Date.now();
      if (verbose) {
        console.info(`was gonna wait too long; new waitTime: ${waitTime}ms`);
      }
    }
    totalWaitTime = waitTime + totalWaitTime;
    attempts.push(await fn(attempts[attempts.length - 1]));
    if (verbose && keepWaitingIf(attempts[attempts.length - 1])) {
      console.info(
        `${count}. Called ${fn}; ${attempts.length} prev attempts. Most recent: ${JSON.stringify(
          attempts[attempts.length - 1],
          null,
          2
        )}`
      );
    }
  }
  return attempts;
}
const contractErrorPattern = /Error\(Contract, #(\d+)\)/;
function implementsToString(obj) {
  return typeof obj === "object" && obj !== null && "toString" in obj;
}
function parseWasmCustomSections(buffer) {
  const sections = /* @__PURE__ */ new Map();
  const arrayBuffer = buffer.buffer.slice(
    buffer.byteOffset,
    buffer.byteOffset + buffer.byteLength
  );
  let offset = 0;
  const read = (length) => {
    if (offset + length > buffer.byteLength) throw new Error("Buffer overflow");
    const bytes = new Uint8Array(arrayBuffer, offset, length);
    offset += length;
    return bytes;
  };
  function readVarUint32() {
    let value = 0;
    let shift = 0;
    while (true) {
      const byte = read(1)[0];
      value |= (byte & 127) << shift;
      if ((byte & 128) === 0) break;
      if ((shift += 7) >= 32) throw new Error("Invalid WASM value");
    }
    return value >>> 0;
  }
  if ([...read(4)].join() !== "0,97,115,109")
    throw new Error("Invalid WASM magic");
  if ([...read(4)].join() !== "1,0,0,0")
    throw new Error("Invalid WASM version");
  while (offset < buffer.byteLength) {
    const sectionId = read(1)[0];
    const sectionLength = readVarUint32();
    const start = offset;
    if (sectionId === 0) {
      const nameLen = readVarUint32();
      if (nameLen > 0 && offset + nameLen <= start + sectionLength) {
        const nameBytes = read(nameLen);
        const payload = read(sectionLength - (offset - start));
        try {
          const name = new TextDecoder("utf-8", { fatal: true }).decode(
            nameBytes
          );
          if (payload.length > 0) {
            sections.set(name, (sections.get(name) || []).concat(payload));
          }
        } catch {
        }
      }
    }
    offset = start + sectionLength;
  }
  return sections;
}
function processSpecEntryStream(buffer) {
  const reader = new jsxdr.default.XdrReader(buffer);
  const res = [];
  while (!reader.eof) {
    res.push(curr_generated.default.ScSpecEntry.read(reader));
  }
  return res;
}
async function getAccount(options, server) {
  return options.publicKey ? server.getAccount(options.publicKey) : new account.Account(types.NULL_ACCOUNT, "0");
}

exports.contractErrorPattern = contractErrorPattern;
exports.getAccount = getAccount;
exports.implementsToString = implementsToString;
exports.parseWasmCustomSections = parseWasmCustomSections;
exports.processSpecEntryStream = processSpecEntryStream;
exports.withExponentialBackoff = withExponentialBackoff;
//# sourceMappingURL=utils.js.map
