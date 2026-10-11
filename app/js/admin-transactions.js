/**
 * Admin calls from the multisig admin account, whose signers each sign the same
 * envelope. Kept out of `admin.js` so Node unit tests can import it.
 */
import {
  Address,
  Keypair,
  SignerKey,
  StrKey,
  Transaction,
  TransactionBuilder,
  contract,
  rpc,
  scValToNative,
} from '@stellar/stellar-sdk';

import { CONTRACT_ERRORS } from './ui/errors.js';

/** Seconds an admin transaction stays valid: a day, since collecting signatures outlasts the SDK's five-minute default. */
const ADMIN_TX_TIMEOUT_SECONDS = 86_400;

/** Returns an RPC client for `rpcUrl`, allowing plain HTTP for a local network. */
export const rpcServer = (rpcUrl) => new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });

/**
 * Builds the unsigned, simulated envelope `{ xdr }` of a contract call whose
 * source is the admin account. A call reading archived entries restores them
 * first, paid by the admin account within the fee `describeAdminCall` shows.
 *
 * @param {{rpcUrl: string, networkPassphrase: string, source: string, contractId: string, method: string, args?: Object}} call
 *   `source` is the contract's admin; `args` are by name.
 * @returns {Promise<{xdr: string}>}
 * @throws {Error} if the contract has no `method`, refuses the call, or has
 *   another admin than `source`.
 */
export async function buildAdminCall({ rpcUrl, networkPassphrase, source, contractId, method, args }) {
  const client = await contract.Client.from({ rpcUrl, networkPassphrase, publicKey: source, contractId, server: rpcServer(rpcUrl) });
  if (typeof client[method] !== 'function') {
    throw new Error(`${contractId} has no ${method} entry point`);
  }
  const options = { timeoutInSeconds: ADMIN_TX_TIMEOUT_SECONDS };
  const tx = await (args ? client[method](args, options) : client[method](options));
  const { simulation } = tx;
  if (rpc.Api.isSimulationError(simulation)) {
    throw new Error(simulation.error);
  }
  const xdr = tx.toXdr();
  // Throws if `source` is not the admin, before anyone signs.
  describeAdminCall(xdr, networkPassphrase);
  return { xdr };
}

/**
 * Describes an admin call for its signers to read before signing.
 *
 * @returns {{source: string, sequence: string, fee: string, validUntil: number, contract: string, method: string, args: Array}}
 *   `fee` is the most the source pays, in stroops; `validUntil` is in Unix seconds.
 * @throws {Error} for a fee bump, any condition but a time bound with an end,
 *   anything but one contract call, or authorization beyond that call by the source.
 */
export function describeAdminCall(xdr, networkPassphrase) {
  const tx = TransactionBuilder.fromXdr(xdr, networkPassphrase);
  // A fee bump's signatures authorize no admin call.
  if (!(tx instanceof Transaction)) {
    throw new Error('the envelope is a fee bump, not an admin call');
  }
  // The card shows only the time bound. A minimum-sequence condition would keep a
  // signed envelope valid past later admin calls; a bound with no end never expires.
  if (tx.toEnvelope().value.tx.cond.type !== 'precondTime' || Number(tx.timeBounds.maxTime) === 0) {
    throw new Error('the envelope carries conditions other than a time bound');
  }
  const [operation, ...others] = tx.operations;
  const call = operation?.func?.invokeContract;
  // A pasted envelope could hide a second, undescribed operation.
  if (others.length > 0 || !call) {
    throw new Error('the envelope holds something other than one contract call');
  }
  // The signatures cover every source-account entry, so another call's entry would
  // run undescribed, and one needing another account's signature would fail.
  const describedCall = ({ credentials, rootInvocation }) =>
    credentials.type === 'sorobanCredentialsSourceAccount'
    && rootInvocation.function.contractFn?.equals(call)
    && rootInvocation.subInvocations.length === 0;
  if ((operation.source && operation.source !== tx.source) || !operation.auth.every(describedCall)) {
    throw new Error('the envelope authorizes something other than this call by its source');
  }
  return {
    source: tx.source,
    sequence: tx.sequence,
    fee: tx.fee,
    validUntil: Number(tx.timeBounds.maxTime),
    contract: Address.fromScAddress(call.contractAddress).toString(),
    method: call.functionName.toString(),
    args: call.args.map(scValToNative),
  };
}

/** Returns the number of signatures an envelope carries. */
export function signatureCount(xdr, networkPassphrase) {
  return TransactionBuilder.fromXdr(xdr, networkPassphrase).signatures.length;
}

/** Reports whether an envelope already carries a signature by `publicKey`. */
export function signedBy(xdr, networkPassphrase, publicKey) {
  const tx = TransactionBuilder.fromXdr(xdr, networkPassphrase);
  const key = Keypair.fromPublicKey(publicKey);
  return tx.signatures.some(({ signature }) => key.verify(tx.hash(), signature));
}

/**
 * Reads an account's signer weights and contract-call threshold.
 *
 * @param {xdr.AccountEntry} account
 * @returns {{threshold: number, weights: Map<string, number>}} `threshold` is the
 *   medium threshold, at least 1 since 0 still takes one signature. `weights`
 *   includes the account's own key.
 */
export function signingRule(account) {
  const [master, , medium] = account.thresholds.value;
  const weights = new Map(account.signers.map(({ key, weight }) => [SignerKey.encodeSignerKey(key), weight]));
  weights.set(StrKey.encodeEd25519PublicKey(account.accountId.ed25519.value), master);
  return { threshold: Math.max(medium, 1), weights };
}

/**
 * Returns why `address` must not sign, or `null` when its signature counts.
 * An unused signature fails the transaction and cannot be removed: a
 * non-signer's, one past the threshold, or a signer's second.
 */
export function signRefusal({ threshold, weights }, xdr, networkPassphrase, address) {
  if (!(weights.get(address) > 0)) {
    return `The connected account does not sign for ${TransactionBuilder.fromXdr(xdr, networkPassphrase).source}`;
  }
  if (signatureCount(xdr, networkPassphrase) >= threshold) {
    return 'The envelope already carries the signatures it needs. Submit it.';
  }
  if (signedBy(xdr, networkPassphrase, address)) {
    return 'This account has already signed the envelope';
  }
  return null;
}

/**
 * Formats a `host_fn_failed` diagnostic event's error the way a failed simulation
 * does, for example `Error(Contract, #20)`, or returns `''`. A failed sent
 * transaction reports its error only in these events.
 */
export function hostError(events = []) {
  const topics = events
    .map(({ event }) => event.body.v0.topics)
    .find(([name]) => scValToNative(name) === 'host_fn_failed');
  if (!topics) return '';
  const { type, contractCode, code } = topics[1].error;
  const detail = type === 'sceContract' ? `#${contractCode}` : code.name.slice('scec'.length);
  return `Error(${type.slice('sce'.length)}, ${detail})`;
}

/**
 * Sends a signed transaction and polls it to a final status.
 *
 * Signatures are not part of the hash, so if another signer already sent it, the
 * network refuses this copy and the result is the copy that landed.
 *
 * @returns {Promise<Object>} The `getTransaction` response.
 * @throws {Error} naming the status, result code, and host error on failure.
 */
export async function submitAdminCall({ rpcUrl, networkPassphrase, xdr, server = rpcServer(rpcUrl) }) {
  const sent = await server.sendTransaction(TransactionBuilder.fromXdr(xdr, networkPassphrase));
  const landed = sent.status === 'PENDING'
    ? await server.pollTransaction(sent.hash, { attempts: 30 })
    : await server.getTransaction(sent.hash);
  if (landed.status === 'SUCCESS') return landed;
  if (sent.status !== 'PENDING' && landed.status === 'NOT_FOUND') {
    throw new Error(`transaction ${sent.status}: ${sent.errorResult?.result.type ?? ''} ${hostError(sent.diagnosticEvents)}`);
  }
  throw new Error(`transaction ${sent.hash} ${landed.status}: ${landed.resultXdr?.result.type ?? ''} ${hostError(landed.diagnosticEventsXdr)}`);
}

// Tested in order: `tx_bad_auth_extra` before `tx_bad_auth`, which also matches it.
const NETWORK_REFUSALS = [
  [/tx_?bad_?auth_?extra/i, 'The transaction carries a signature it does not use: more than the threshold needs, one signer twice, or a key that is not a signer. Build the call again and collect the threshold\'s signatures, one from each signer.'],
  [/tx_?bad_?auth/i, 'The transaction lacks signatures. Collect more from the admin account\'s signers.'],
  [/tx_?bad_?seq/i, 'Another admin transaction used the sequence number first. Build the call again.'],
  [/tx_?too_?late/i, 'The transaction\'s time bound has passed. Build the call again.'],
  [/TRY_AGAIN_LATER|NOT_FOUND|DUPLICATE/, 'The network has not confirmed the transaction yet. Check the contract before building the call again.'],
  [/Error\(Auth, InvalidAction\)/, 'The transaction\'s source is not the contract\'s admin.'],
  [/Error\(Budget, ExceededLimit\)/, 'The call needs more resources than one transaction allows. For a blocklist insert, add fewer keys at a time.'],
];

/**
 * Explains why an admin transaction failed, or returns the error's own message.
 *
 * @param {Error|string} error
 * @param {'pool'|'asp-membership'|'asp-non-membership'|'unknown'} [kind] The contract kind.
 */
export function explainFailure(error, kind) {
  const message = error?.message ?? String(error);
  const refusal = NETWORK_REFUSALS.find(([pattern]) => pattern.test(message));
  if (refusal) return refusal[1];
  const code = Number(/Error\(Contract, #(\d+)\)/.exec(message)?.[1]);
  if (kind === 'pool' && code >= 18 && CONTRACT_ERRORS.pool[code]) return CONTRACT_ERRORS.pool[code];
  // Codes differ by contract: #6 is an allowlist's `NoPendingAdmin` but a blocklist's `Overflow`.
  return ({ 'asp-membership': CONTRACT_ERRORS.aspMembership, 'asp-non-membership': CONTRACT_ERRORS.aspNonMembership })[kind]?.[code] ?? message;
}
