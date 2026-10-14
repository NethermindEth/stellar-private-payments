/**
 * Deposit pauses the admin's signers authorize ahead of time, for a holder to send
 * from their own account. Kept out of `admin.js` so Node unit tests can import it.
 */
import {
  Account,
  Address,
  BASE_FEE,
  Contract,
  Keypair,
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

import { rpcServer } from './admin-transactions.js';

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

// Compares public keys byte by byte, the order the host requires of an account's signatures.
function compareKeys(a, b) {
  const index = a.findIndex((byte, i) => byte !== b[i]);
  return index === -1 ? 0 : a[index] - b[index];
}

/**
 * Returns a copy of `entry` with a signer's Ed25519 signature of the preimage's
 * hash added, signatures kept sorted by public key.
 *
 * @throws {Error} when `publicKey` already signed, or `signature` is not its
 *   signature of the preimage on that network.
 */
export function addSignature(entry, publicKey, signature, networkPassphrase) {
  const credentials = entry.credentials.address;
  const key = StrKey.decodeEd25519PublicKey(publicKey);
  const signatures = scValToNative(credentials.signature);
  if (signatures.some(({ public_key: signed }) => compareKeys(signed, key) === 0)) {
    throw new Error(`${publicKey} has already signed the authorization`);
  }
  // A bad signature would otherwise surface only when a holder sends the pause.
  if (!Keypair.fromPublicKey(publicKey).verify(hash(preimage(entry, networkPassphrase).toXdr()), signature)) {
    throw new Error(`The signature is not ${publicKey}'s signature of the authorization on this network`);
  }
  signatures.push({ public_key: key, signature });
  signatures.sort((a, b) => compareKeys(a.public_key, b.public_key));
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      ...credentials,
      signature: nativeToScVal(signatures, { type: { public_key: ['symbol', null], signature: ['symbol', null] } }),
    })),
    rootInvocation: entry.rootInvocation,
  });
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
 * Writes the file a holder keeps: the pool, the holder, the nonce, the expiration
 * ledger, the signers, and the entry. Every field but `holder` is read from the entry.
 *
 * @returns {string} The file's JSON.
 * @throws {Error} when the entry authorizes anything but `pause_deposits()` on one pool.
 */
export function encodeAuthorization({ holder, entry }) {
  const { pool, nonce, expirationLedger, signers } = describePause(entry);
  return JSON.stringify({
    pool,
    holder,
    nonce: nonce.toString(),
    expirationLedger,
    signers,
    entry: entry.toXdr('base64'),
  }, null, 2);
}

/**
 * Reads a file `encodeAuthorization` wrote. Every field but `holder` comes from
 * the entry, so an edited field cannot misdescribe it.
 *
 * @returns {{pool: string, admin: string, holder: string, nonce: bigint, expirationLedger: number, signers: string[], entry: xdr.SorobanAuthorizationEntry}}
 * @throws {Error} when the entry authorizes anything but `pause_deposits()` on one pool.
 */
export function decodeAuthorization(text) {
  const { holder, entry } = JSON.parse(text);
  const decoded = xdr.SorobanAuthorizationEntry.fromXdr(entry, 'base64');
  return { ...describePause(decoded), holder, entry: decoded };
}

/**
 * Builds the unsigned, simulated envelope `{ xdr }` that sends a pre-signed pause
 * from the holder's account `source`, or returns `{ paused: true }` for a paused
 * pool, where sending would only spend the authorization. Simulation checks the
 * signatures, so a bad one fails here, not on chain. An archived `Admin` entry is
 * restored at the holder's cost.
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
    throw new Error(`The authorization expired at ledger ${expirationLedger}. The signers sign a new one.`);
  }
  const build = (account, operation, fee = BASE_FEE) => new TransactionBuilder(account, { fee, networkPassphrase })
    .addOperation(operation)
    .setTimeout(contract.DEFAULT_TIMEOUT)
    .build();
  const simulate = async (tx) => {
    const simulation = await server.simulateTransaction(tx);
    if (rpc.Api.isSimulationError(simulation)) throw new Error(simulation.error);
    return simulation;
  };
  const read = await simulate(build(new Account(contract.NULL_ACCOUNT, '0'), new Contract(pool).call('deposits_paused')));
  if (scValToNative(read.result.retval)) return { paused: true };
  // Bids the 99th percentile of recent Soroban inclusion fees, never below the minimum, so the pause lands in a fee surge.
  const [account, { sorobanInclusionFee }] = await Promise.all([server.getAccount(source), server.getFeeStats()]);
  const tx = build(
    account,
    Operation.invokeContractFunction({ contract: pool, function: 'pause_deposits', args: [], auth: [entry] }),
    String(Math.max(Number(BASE_FEE), Number(sorobanInclusionFee.p99))),
  );
  const simulation = await simulate(tx).catch((err) => {
    // The host refuses an entry whose nonce a landed pause spent.
    if (/Error\(Auth, ExistingValue\)/.test(err.message)) {
      throw new Error('The file has already been used. The signers sign a new file.');
    }
    // Too few signatures, a removed signer's, or a previous admin's.
    if (!/Error\(Auth, InvalidAction\)/.test(err.message)) throw err;
    throw new Error('The file does not authorize the pause: it carries too few signatures, a removed signer\'s, or a previous admin\'s. The signers sign a new file.');
  });
  // No `deposit_pause_changed` event means the pool is paused, and sending would only spend the file.
  if (!simulation.events.some(({ event }) => scValToNative(event.body.v0.topics[0]) === 'deposit_pause_changed')) {
    return { paused: true };
  }
  return { xdr: rpc.assembleTransaction(tx, simulation).build().toXdr() };
}
