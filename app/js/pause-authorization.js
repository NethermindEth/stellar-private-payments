/**
 * Deposit pauses the admin's signers authorize ahead of time, for whoever keeps the
 * file to send from their own account. Kept out of `admin.js` so Node unit tests can import it.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  Operation,
  StrKey,
  TransactionBuilder,
  contract,
  hash,
  nativeToScVal,
  rpc,
  scValToNative,
  xdr,
} from '@stellar/stellar-sdk';

import { hex, rpcServer, shortAddress } from './admin-transactions.js';

/**
 * Builds an unsigned authorization, by a pool's admin, of one `pause_deposits()`
 * on the pool, expiring `maxEntryTtl - 1` ledgers after `latestLedger`, the
 * latest the host accepts.
 *
 * @param {{admin: string, pool: string, nonce: bigint, latestLedger: number, maxEntryTtl: number}} pause
 *   `nonce` is a random `i64`, spent when the pause lands.
 * @returns {xdr.SorobanAuthorizationEntry}
 */
export function buildPauseAuthorization({ admin, pool, nonce, latestLedger, maxEntryTtl }) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(admin).toScAddress(),
      nonce,
      signatureExpirationLedger: latestLedger + maxEntryTtl - 1,
      signature: xdr.ScVal.scvVec([]),
    })),
    rootInvocation: new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(new xdr.InvokeContractArgs({
        contractAddress: new Address(pool).toScAddress(),
        functionName: 'pause_deposits',
        args: [],
      })),
      subInvocations: [],
    }),
  });
}

/** Returns the preimage each signer signs, as the base64 `HashIdPreimage` XDR Freighter's `signAuthEntry` takes. */
export function authorizationPreimage(entry, networkPassphrase) {
  return preimage(entry, networkPassphrase).toXdr('base64');
}

// Returns the `HashIdPreimage` whose SHA-256 hash each signer signs.
function preimage(entry, networkPassphrase) {
  const { nonce, signatureExpirationLedger } = entry.credentials.address;
  return xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(new xdr.HashIdPreimageSorobanAuthorization({
    networkId: hash(networkPassphrase),
    nonce,
    signatureExpirationLedger,
    invocation: entry.rootInvocation,
  }));
}

// Ed25519 scalars are little-endian.
const littleEndian = (bytes) => BigInt(`0x${hex(Uint8Array.from(bytes).reverse())}`);

// Matches the host's ed25519-dalek `verify_strict`. `Keypair.verify` is cofactored
// and accepts signatures the host rejects.
function verifiesAsHost(publicKey, message, signature) {
  if (signature.length !== 64) return false;
  const order = ed.Point.CURVE().n;
  try {
    const encodedR = signature.subarray(0, 32);
    const s = littleEndian(signature.subarray(32));
    const A = ed.Point.fromBytes(publicKey);
    const R = ed.Point.fromBytes(encodedR);
    if (s >= order || A.isSmallOrder() || R.isSmallOrder()) return false;
    const k = ed.etc.mod(littleEndian(sha512(ed.etc.concatBytes(encodedR, publicKey, message))), order);
    const expected = ed.Point.BASE.multiply(s, false).subtract(A.multiply(k, false));
    return hex(expected.toBytes()) === hex(encodedR);
  } catch {
    return false;
  }
}

// Compares public keys byte by byte, the order the host requires of an account's signatures.
function compareKeys(a, b) {
  const index = a.findIndex((byte, i) => byte !== b[i]);
  return index === -1 ? 0 : a[index] - b[index];
}

/** Adds one signature. Throws on a duplicate or invalid one. */
export function addSignature(entry, publicKey, signature, networkPassphrase) {
  const credentials = entry.credentials.address;
  const key = StrKey.decodeEd25519PublicKey(publicKey);
  const signatures = scValToNative(credentials.signature);
  if (signatures.some(({ public_key: signed }) => compareKeys(signed, key) === 0)) {
    throw new Error(`${shortAddress(publicKey)} has already signed this file`);
  }
  // A bad signature would otherwise surface only when the pause is sent.
  if (!verifiesAsHost(key, hash(preimage(entry, networkPassphrase).toXdr()), signature)) {
    throw new Error(`Not a valid signature from ${shortAddress(publicKey)} on this network`);
  }
  signatures.push({ public_key: key, signature });
  signatures.sort((a, b) => compareKeys(a.public_key, b.public_key));
  return withSignatures(entry, signatures);
}

const withSignatures = (entry, signatures) => new xdr.SorobanAuthorizationEntry({
  credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
    ...entry.credentials.address,
    signature: nativeToScVal(signatures, { type: { public_key: ['symbol', null], signature: ['symbol', null] } }),
  })),
  rootInvocation: entry.rootInvocation,
});

/** Adds another copy's counted signatures, up to the threshold, so swapping a signer voids it. */
export function mergeSignatures(entry, other, networkPassphrase, rule) {
  const { signers } = describePause(entry);
  let merged = entry;
  let weight = pauseFileWeight({ signers }, rule);
  for (const { public_key: key, signature } of scValToNative(other.credentials.address.signature)) {
    const signer = StrKey.encodeEd25519PublicKey(key);
    const counts = rule.weights.get(signer) ?? 0;
    if (signers.includes(signer) || counts <= 0 || weight >= rule.threshold) continue;
    merged = addSignature(merged, signer, signature, networkPassphrase);
    weight += counts;
  }
  return merged;
}

/** Rechecks every signature. Throws on the first bad or duplicate one. */
export function verifySignatures(entry, networkPassphrase) {
  return scValToNative(entry.credentials.address.signature).reduce(
    (verified, { public_key: key, signature }) => addSignature(verified, StrKey.encodeEd25519PublicKey(key), signature, networkPassphrase),
    withSignatures(entry, []),
  );
}

export const uncountedSigners = ({ signers }, { weights }) => signers.filter((key) => !(weights.get(key) > 0));

/** Drops zero-weight signatures: the host rejects the whole entry over one. */
export function countedEntry(entry, { weights }) {
  const counted = scValToNative(entry.credentials.address.signature)
    .filter(({ public_key: key }) => weights.get(StrKey.encodeEd25519PublicKey(key)) > 0);
  return withSignatures(entry, counted);
}

/**
 * Decodes the `signedAuthEntry` field of Freighter's `signAuthEntry` result into
 * the bytes `addSignature` takes.
 *
 * @throws {Error} when the wallet returned no signature.
 */
export function walletSignature(signedAuthEntry) {
  if (!signedAuthEntry) throw new Error('The wallet returned no signature');
  return Uint8Array.from(atob(signedAuthEntry), (char) => char.charCodeAt(0));
}

// Reads a pause authorization's pool, admin, nonce, expiry, and signers. Files can
// come from anyone, so an entry for any other call is refused.
function describePause(entry) {
  const call = entry.rootInvocation.function.contractFn;
  if (
    entry.credentials.type !== 'sorobanCredentialsAddress'
    || call?.functionName.toString() !== 'pause_deposits'
    || call.args.length > 0
    || entry.rootInvocation.subInvocations.length > 0
  ) {
    throw new Error('The file authorizes something other than a pause of one pool\'s deposits');
  }
  const { address, nonce, signatureExpirationLedger, signature } = entry.credentials.address;
  return {
    pool: Address.fromScAddress(call.contractAddress).toString(),
    admin: Address.fromScAddress(address).toString(),
    nonce,
    expirationLedger: signatureExpirationLedger,
    signers: scValToNative(signature).map(({ public_key: key }) => StrKey.encodeEd25519PublicKey(key)),
  };
}

/**
 * Writes a pause file: the entry, preceded by its pool, nonce, expiration ledger,
 * and signers for a reader.
 *
 * @returns {string} The file's JSON.
 * @throws {Error} when the entry authorizes anything but `pause_deposits()` on one pool.
 */
export function encodeAuthorization(entry) {
  const { pool, nonce, expirationLedger, signers } = describePause(entry);
  return JSON.stringify({
    pool,
    nonce: nonce.toString(),
    expirationLedger,
    signers,
    entry: entry.toXdr('base64'),
  }, null, 2);
}

export const describeAuthorization = (entry) => ({ ...describePause(entry), entry });

// Master key plus at most 20 signers.
const MAX_KEYS = 21;

/** Reads a pause file. Every field comes from the entry, so edited fields can't lie. */
export function decodeAuthorization(text) {
  let decoded;
  try {
    decoded = xdr.SorobanAuthorizationEntry.fromXdr(JSON.parse(text).entry, 'base64');
  } catch {
    throw new Error('This is not a pause file');
  }
  const authorization = describeAuthorization(decoded);
  if (authorization.signers.length > MAX_KEYS) throw new Error('This file carries more signatures than an admin account has keys');
  return authorization;
}

/** Approximate day `ledger` closes, at 5 s a ledger. */
export const ledgerDate = (ledger, latestLedger, now = Date.now()) => new Date(now + (ledger - latestLedger) * 5_000).toISOString().slice(0, 10);

// Host limit per authorization.
const MAX_SIGNATURES = 20;

const SIGN_AGAIN = 'The signers need to sign a new file.';

export const pauseFileWeight = ({ signers }, { weights }) => signers.reduce((sum, key) => sum + (weights.get(key) ?? 0), 0);

/** Why the file can never pause its pool, or null. */
export function pauseFileProblem({ admin, expirationLedger, signers }, { poolAdmin, rule, latestLedger, maxEntryTtl, spent }) {
  if (spent) return `Already used. ${SIGN_AGAIN}`;
  if (expirationLedger <= latestLedger) return `Expired around ${ledgerDate(expirationLedger, latestLedger)}. ${SIGN_AGAIN}`;
  // The host rejects an expiration past max_entry_ttl.
  if (expirationLedger > latestLedger + maxEntryTtl) {
    return `The network now limits how long a file lasts. This one works only from about ${ledgerDate(expirationLedger - maxEntryTtl, latestLedger)}. ${SIGN_AGAIN}`;
  }
  if (admin !== poolAdmin) return `Made for ${shortAddress(admin)}, but the pool's admin is now ${shortAddress(poolAdmin)}. ${SIGN_AGAIN}`;
  // Only counted signatures are sent.
  const counted = signers.length - uncountedSigners({ signers }, rule).length;
  return counted > MAX_SIGNATURES ? `${counted} signatures, but the network takes at most ${MAX_SIGNATURES}. ${SIGN_AGAIN}` : null;
}

/** One of `{ problem }`, `{ short }`, `{ paused }` or `{ ready }`. */
export function pauseFileState(authorization, chain) {
  const problem = pauseFileProblem(authorization, chain);
  if (problem) return { problem };
  if (pauseFileWeight(authorization, chain.rule) < chain.rule.threshold) return { short: true };
  return chain.paused ? { paused: true } : { ready: true };
}

const oneOperation = (account, operation, networkPassphrase, fee = BASE_FEE) => new TransactionBuilder(account, { fee, networkPassphrase })
  .addOperation(operation)
  .setTimeout(contract.DEFAULT_TIMEOUT)
  .build();

async function simulated(server, tx) {
  const simulation = await server.simulateTransaction(tx);
  if (rpc.Api.isSimulationError(simulation)) throw new Error(simulation.error);
  return simulation;
}

/** The host keeps a spent nonce until the file expires, so any used copy reads as spent. */
export async function nonceSpent(server, admin, nonce) {
  const key = xdr.LedgerKey.contractData(new xdr.LedgerKeyContractData({
    contract: new Address(admin).toScAddress(),
    key: xdr.ScVal.scvLedgerKeyNonce(new xdr.ScNonceKey({ nonce })),
    durability: xdr.ContractDataDurability.temporary,
  }));
  const { entries } = await server.getLedgerEntries(key);
  return entries.length > 0;
}

export async function depositsPaused(server, pool, networkPassphrase) {
  const read = await simulated(server, oneOperation(new Account(contract.NULL_ACCOUNT, '0'), new Contract(pool).call('deposits_paused'), networkPassphrase));
  return scValToNative(read.result.retval);
}

/**
 * Builds the unsigned, simulated envelope `{ xdr }` that sends a pre-signed pause
 * from any funded account `source`, or returns `{ paused: true }` for a paused
 * pool, where sending would only spend the authorization. Simulation checks the
 * signatures, so a bad one fails here, not on chain. An archived `Admin` entry is
 * restored at the cost of `source`.
 *
 * @param {{rpcUrl: string, networkPassphrase: string, source: string, authorization: Object, server?: rpc.Server}} pause
 *   `authorization` is a file read by `decodeAuthorization`.
 * @returns {Promise<{xdr: string}|{paused: true}>}
 * @throws {Error} when the authorization expired or the host refuses it, or with
 *   the simulation's error when the pool refuses the read or the pause.
 */
export async function pauseTransaction({ rpcUrl, networkPassphrase, source, authorization, server = rpcServer(rpcUrl) }) {
  const { pool, expirationLedger, entry } = authorization;
  const { sequence } = await server.getLatestLedger();
  if (expirationLedger <= sequence) {
    throw new Error(`Expired. ${SIGN_AGAIN}`);
  }
  if (await depositsPaused(server, pool, networkPassphrase)) return { paused: true };
  // Bids the 99th percentile of recent Soroban inclusion fees, never below the minimum, so the pause lands in a fee surge.
  const [account, { sorobanInclusionFee }] = await Promise.all([server.getAccount(source), server.getFeeStats()]);
  const tx = oneOperation(
    account,
    Operation.invokeContractFunction({ contract: pool, function: 'pause_deposits', args: [], auth: [entry] }),
    networkPassphrase,
    String(Math.max(Number(BASE_FEE), Number(sorobanInclusionFee.p99))),
  );
  const simulation = await simulated(server, tx).catch((err) => {
    // The host refuses an entry whose nonce a landed pause spent.
    if (/Error\(Auth, ExistingValue\)/.test(err.message)) {
      throw new Error(`Already used. ${SIGN_AGAIN}`);
    }
    if (!/Error\(Auth, InvalidAction\)/.test(err.message)) throw err;
    throw new Error(`The network refused the file's signatures. ${SIGN_AGAIN}`);
  });
  // No `deposit_pause_changed` event means the pool is paused, and sending would only spend the file.
  if (!simulation.events.some(({ event }) => scValToNative(event.body.v0.topics[0]) === 'deposit_pause_changed')) {
    return { paused: true };
  }
  return { xdr: rpc.assembleTransaction(tx, simulation).build().toXdr() };
}
