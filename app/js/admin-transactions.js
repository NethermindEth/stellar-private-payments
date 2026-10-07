/**
 * Admin calls from the multisig admin account, whose signers each sign the
 * same envelope.
 *
 * Separate from `admin.js` so Node can import it in unit tests.
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

/**
 * Seconds an admin transaction stays valid. Collecting signatures outlasts
 * `contract.Client`'s five-minute default.
 */
const ADMIN_TX_TIMEOUT_SECONDS = 86_400;

/**
 * Returns an RPC client for `rpcUrl`, allowing plain HTTP for a local network.
 *
 * @param {string} rpcUrl
 * @returns {rpc.Server}
 */
export const rpcServer = (rpcUrl) => new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });

/**
 * Builds an unsigned contract call whose source is the admin account.
 *
 * Returns `{ xdr }`, the simulated envelope to sign. A call that reads
 * archived entries restores them, at the admin account's cost, within the fee
 * `describeAdminCall` shows.
 *
 * @param {Object} call
 * @param {string} call.rpcUrl - The RPC that simulates the call.
 * @param {string} call.networkPassphrase - The network to build the call for.
 * @param {string} call.source - The contract's admin, the transaction's source.
 * @param {string} call.contractId - The contract to call.
 * @param {string} call.method - The entry point to call.
 * @param {Object} [call.args] - Arguments by name; omit for none.
 * @returns {Promise<{xdr: string}>}
 * @throws {Error} when the contract has no `method` entry point, with the
 *   simulation's error when the contract refuses the call, and when `source`
 *   is not the contract's admin.
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
  // Throws when `source` is not the contract's admin, before anyone signs an
  // authorization the signers cannot give.
  describeAdminCall(xdr, networkPassphrase);
  return { xdr };
}

/**
 * Describes an admin call for its signers to read before they sign it.
 *
 * @param {string} xdr - Transaction envelope XDR (base64).
 * @param {string} networkPassphrase - The network the envelope was built for.
 * @returns {{source: string, sequence: string, fee: string, validUntil: number, contract: string, method: string, args: Array}}
 *   `fee` is the most the source pays, in stroops. `validUntil` is the end of
 *   the time bound in Unix seconds.
 * @throws {Error} when the envelope is a fee bump, carries any condition but
 *   a time bound with an end, holds anything but one contract call, or
 *   authorizes anything but that call by the transaction's source.
 */
export function describeAdminCall(xdr, networkPassphrase) {
  const tx = TransactionBuilder.fromXdr(xdr, networkPassphrase);
  // A fee bump's signatures pay for an inner transaction from any account and
  // authorize no admin call.
  if (!(tx instanceof Transaction)) {
    throw new Error('the envelope is a fee bump, not an admin call');
  }
  // The card shows only the time bound. A minimum-sequence condition would
  // keep a signed envelope valid past later admin transactions, and a bound
  // with no end never expires.
  if (tx.toEnvelope().value.tx.cond.type !== 'precondTime' || Number(tx.timeBounds.maxTime) === 0) {
    throw new Error('the envelope carries conditions other than a time bound');
  }
  const [operation, ...others] = tx.operations;
  const call = operation?.func?.invokeContract;
  // A pasted envelope could hide a second, undescribed operation.
  if (others.length > 0 || !call) {
    throw new Error('the envelope holds something other than one contract call');
  }
  // The signatures cover every source-account entry, so an entry for another
  // call would act undescribed; one needing another account's signature would
  // make the call fail.
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

/**
 * Returns the number of signatures an envelope carries.
 *
 * @param {string} xdr - Transaction envelope XDR (base64).
 * @param {string} networkPassphrase - The network the envelope was built for.
 * @returns {number}
 */
export function signatureCount(xdr, networkPassphrase) {
  return TransactionBuilder.fromXdr(xdr, networkPassphrase).signatures.length;
}

/**
 * Reports whether an envelope already carries a signature by `publicKey`.
 *
 * @param {string} xdr - Transaction envelope XDR (base64).
 * @param {string} networkPassphrase - The network the envelope was built for.
 * @param {string} publicKey - The signer's account address.
 * @returns {boolean}
 */
export function signedBy(xdr, networkPassphrase, publicKey) {
  const tx = TransactionBuilder.fromXdr(xdr, networkPassphrase);
  const key = Keypair.fromPublicKey(publicKey);
  return tx.signatures.some(({ signature }) => key.verify(tx.hash(), signature));
}

/**
 * Reads an account's signer weights and contract-call threshold from its
 * ledger entry.
 *
 * @param {xdr.AccountEntry} account
 * @returns {{threshold: number, weights: Map<string, number>}} `threshold` is
 *   the medium threshold, at least 1 since 0 still takes one signature.
 *   `weights` maps each signing key, the account's own included, to its weight.
 */
export function signingRule(account) {
  const [master, , medium] = account.thresholds.value;
  const weights = new Map(account.signers.map(({ key, weight }) => [SignerKey.encodeSignerKey(key), weight]));
  weights.set(StrKey.encodeEd25519PublicKey(account.accountId.ed25519.value), master);
  return { threshold: Math.max(medium, 1), weights };
}

/**
 * Returns why `address` must not sign an admin call, or `null` when its
 * signature counts toward the threshold.
 *
 * An unused signature fails the transaction and cannot be removed: a
 * non-signer's, one past the threshold, or a signer's second.
 *
 * @param {{threshold: number, weights: Map<string, number>}} rule - The
 *   source's `signingRule`.
 * @param {string} xdr - Transaction envelope XDR (base64).
 * @param {string} networkPassphrase - The network the envelope was built for.
 * @param {string} address - The signer's account address.
 * @returns {string|null}
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
 * Formats a `host_fn_failed` diagnostic event's error as a failed simulation
 * does, for example `Error(Contract, #20)`. A failed sent transaction reports
 * its error only in these events, so `explainFailure` can read both.
 *
 * @param {Array} [events] - The transaction's diagnostic events.
 * @returns {string} The error, or an empty string when no event reports one.
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
 * Signatures are not part of a transaction's hash, so if another signer
 * already sent it, the network refuses this copy and the result is the copy
 * that landed: returned on success, its failure thrown otherwise.
 *
 * @param {Object} submission
 * @param {string} submission.rpcUrl - The RPC to send the transaction to.
 * @param {string} submission.networkPassphrase - The network the envelope was built for.
 * @param {string} submission.xdr - Signed transaction envelope XDR (base64).
 * @param {rpc.Server} [submission.server] - The RPC client, built from
 *   `rpcUrl` when omitted.
 * @returns {Promise<Object>} The RPC's `getTransaction` response.
 * @throws {Error} naming the status, the result code, and the host error when
 *   the transaction does not succeed.
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

// Refusals the page explains, tested in order: `tx_bad_auth_extra` comes
// before the shorter `tx_bad_auth`, which also matches it.
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
 * Explains why an admin transaction failed.
 *
 * @param {Error|string} error
 * @param {'pool'|'asp-membership'|'asp-non-membership'|'unknown'} [kind] - The kind of contract called.
 * @returns {string} The explanation, or the error's own message when it is
 *   not a failure this page explains.
 */
export function explainFailure(error, kind) {
  const message = error?.message ?? String(error);
  const refusal = NETWORK_REFUSALS.find(([pattern]) => pattern.test(message));
  if (refusal) return refusal[1];
  const code = Number(/Error\(Contract, #(\d+)\)/.exec(message)?.[1]);
  if (kind === 'pool' && code >= 18 && CONTRACT_ERRORS.pool[code]) return CONTRACT_ERRORS.pool[code];
  // Codes differ by contract: #6 is an allowlist's `NoPendingAdmin` but a
  // blocklist's `Overflow`; a blocklist's `NoPendingAdmin` is #7, the pools'
  // `InvalidProof`.
  return ({ 'asp-membership': CONTRACT_ERRORS.aspMembership, 'asp-non-membership': CONTRACT_ERRORS.aspNonMembership })[kind]?.[code] ?? message;
}
