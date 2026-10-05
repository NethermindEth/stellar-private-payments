/**
 * Deposit pauses that the admin account's signers authorize ahead of time, for
 * a holder to send from the holder's own account when deposits must stop.
 *
 * Kept apart from `admin.js`, which wires the page, so Node can import it for
 * unit testing.
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
 * The network's `max_entry_ttl` setting in ledgers, 3,110,400 on testnet and
 * mainnet when read on 2026-09-21. The host refuses an authorization whose
 * expiration lies more than `max_entry_ttl - 1` ledgers past the ledger that
 * uses it.
 */
const MAX_ENTRY_TTL = 3_110_400;

/**
 * Builds an unsigned authorization, by a pool's admin, of one
 * `pause_deposits()` call on the pool.
 *
 * The authorization expires `MAX_ENTRY_TTL - 1` ledgers after `latestLedger`,
 * the furthest ahead the host accepts. Any later ledger that uses it lies
 * closer to that expiration, so the host accepts it until it expires.
 *
 * @param {Object} pause
 * @param {string} pause.admin - The pool's admin, whose signers sign the authorization.
 * @param {string} pause.pool - The pool to pause.
 * @param {bigint} pause.nonce - A random `i64`, spent when the pause lands.
 * @param {number} pause.latestLedger - The network's latest ledger.
 * @returns {xdr.SorobanAuthorizationEntry}
 */
export function buildPauseAuthorization({ admin, pool, nonce, latestLedger }) {
  return new xdr.SorobanAuthorizationEntry({
    credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(new xdr.SorobanAddressCredentials({
      address: new Address(admin).toScAddress(),
      nonce,
      signatureExpirationLedger: latestLedger + MAX_ENTRY_TTL - 1,
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

/**
 * Returns the preimage each signer signs for an authorization, as the
 * base64 `HashIdPreimage` XDR that Freighter's `signAuthEntry` takes.
 *
 * @param {xdr.SorobanAuthorizationEntry} entry
 * @param {string} networkPassphrase - The network the authorization is for.
 * @returns {string}
 */
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

// Compares two public keys byte by byte, the order the host requires of an
// account's signatures.
function compareKeys(a, b) {
  const index = a.findIndex((byte, i) => byte !== b[i]);
  return index === -1 ? 0 : a[index] - b[index];
}

/**
 * Adds a signer's signature to an authorization, keeping the signatures
 * sorted by public key.
 *
 * @param {xdr.SorobanAuthorizationEntry} entry
 * @param {string} publicKey - The signer's account address.
 * @param {Uint8Array} signature - The signer's Ed25519 signature of the
 *   preimage's SHA-256 hash.
 * @param {string} networkPassphrase - The network the authorization is for.
 * @returns {xdr.SorobanAuthorizationEntry} A new entry carrying the signature.
 * @throws {Error} when `publicKey` has already signed the authorization, or
 *   when `signature` is not its signature of the preimage on that network.
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
 * Decodes the signature that Freighter's `signAuthEntry` returns into the
 * bytes `addSignature` takes.
 *
 * @param {(string|null)} signedAuthEntry - The `signedAuthEntry` field of
 *   `signAuthEntry`'s result: the base64 signature of the preimage's hash.
 * @returns {Uint8Array}
 * @throws {Error} when the wallet returned no signature.
 */
export function walletSignature(signedAuthEntry) {
  if (!signedAuthEntry) throw new Error('The wallet returned no signature');
  return Uint8Array.from(atob(signedAuthEntry), (char) => char.charCodeAt(0));
}

// Reads what an authorization pauses, who authorizes it, and who has signed.
// A file can come from anyone, so an entry for any other call is refused
// before a signer signs it.
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
 * Writes the file a holder keeps: the pool, the holder, the nonce, the
 * expiration ledger, the signers, and the authorization entry itself.
 *
 * Every field but `holder` is read from the entry.
 *
 * @param {Object} authorization
 * @param {string} authorization.holder - Who keeps the file.
 * @param {xdr.SorobanAuthorizationEntry} authorization.entry
 * @returns {string} The file's JSON.
 * @throws {Error} when the entry authorizes anything but `pause_deposits()`
 *   on one pool.
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
 * Reads a file that `encodeAuthorization` wrote.
 *
 * Every field but `holder` is read from the entry, so an edited field cannot
 * misdescribe it.
 *
 * @param {string} text - The file's JSON.
 * @returns {{pool: string, admin: string, holder: string, nonce: bigint, expirationLedger: number, signers: string[], entry: xdr.SorobanAuthorizationEntry}}
 *   `admin` is the account the entry authorizes for.
 * @throws {Error} when the entry authorizes anything but `pause_deposits()`
 *   on one pool.
 */
export function decodeAuthorization(text) {
  const { holder, entry } = JSON.parse(text);
  const decoded = xdr.SorobanAuthorizationEntry.fromXdr(entry, 'base64');
  return { ...describePause(decoded), holder, entry: decoded };
}

/**
 * Builds the transaction that sends a pre-signed pause from a holder's
 * account.
 *
 * Returns `{ xdr }`, the simulated, unsigned envelope for the holder to sign,
 * or `{ paused: true }`, building nothing, when the pool is already paused:
 * a pause sent there would succeed, change nothing, and spend the
 * authorization. The simulation enforces the entry, so a signature that is
 * missing or wrong fails here rather than on chain. When the pool's `Admin`
 * entry is archived, the pause restores it, and the holder pays for that.
 *
 * @param {Object} pause
 * @param {string} pause.rpcUrl - The RPC that simulates the pause.
 * @param {string} pause.networkPassphrase - The network to build the pause for.
 * @param {string} pause.source - The holder's account, the transaction's source.
 * @param {Object} pause.authorization - A file read by `decodeAuthorization`.
 * @param {rpc.Server} [pause.server] - The RPC client, built from `rpcUrl`
 *   when omitted.
 * @returns {Promise<{xdr: string}|{paused: true}>}
 * @throws {Error} when the authorization has expired or the host refuses
 *   it, and with the simulation's error when the pool refuses the read or the
 *   pause.
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
  // A pause is sent when deposits must stop now, so it bids the 99th
  // percentile of the inclusion fees recent Soroban transactions paid, and
  // never less than the minimum, to land while fees surge.
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
    // The host refuses an entry this way when it carries too few signatures, a
    // removed signer's, or a previous admin's.
    if (!/Error\(Auth, InvalidAction\)/.test(err.message)) throw err;
    throw new Error('The file does not authorize the pause: it carries too few signatures, a removed signer\'s, or a previous admin\'s. The signers sign a new file.');
  });
  // A pause on a paused pool publishes `deposit_pause_repeated` and no
  // `DepositPauseChanged` event, which `#[contractevent]` names
  // `deposit_pause_changed`. Its footprint leaves the pool's instance
  // unwritten, so an unpause that lands first would make it fail on chain and
  // publish the authorization unspent.
  if (!simulation.events.some(({ event }) => scValToNative(event.body.v0.topics[0]) === 'deposit_pause_changed')) {
    return { paused: true };
  }
  return { xdr: rpc.assembleTransaction(tx, simulation).build().toXdr() };
}
