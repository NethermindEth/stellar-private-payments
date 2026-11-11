/**
 * Admin calls the operator SDK builds, signed by each signer of the multisig
 * admin account in turn. Kept out of `admin.js` so Node unit tests can import it.
 */
import {
    Address,
    Keypair,
    SignerKey,
    StrKey,
    Transaction,
    TransactionBuilder,
    rpc,
    scValToNative,
    xdr,
} from "@stellar/stellar-sdk";

import { CONTRACT_ERRORS } from "./ui/errors.js";

export const hex = (bytes) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

export const shortAddress = (address) =>
    `${address.slice(0, 6)}...${address.slice(-4)}`;

// Above the RPC's own 25 s limit, so a slow request still gets the RPC's answer.
const RPC_TIMEOUT_MS = 30_000;

/** The RPC didn't answer. Retrying is the only fix, so callers add no advice. */
export class NoAnswer extends Error {
    constructor(cause) {
        super("The network didn't answer. Try again in a moment.", { cause });
    }
}

// The SDK reports any failed account read as "not found". getAccount and contract.Client use this.
class AdminRpcServer extends rpc.Server {
    async getAccountEntry(address) {
        const key = xdr.LedgerKey.account(
            new xdr.LedgerKeyAccount({
                accountId: Keypair.fromPublicKey(address).xdrPublicKey(),
            }),
        );
        const { entries } = await this.getLedgerEntries(key);
        if (entries.length === 0)
            throw new Error(
                `${shortAddress(
                    address,
                )} isn't an account on this network. Check the address, or fund the account first.`,
            );
        return entries[0].val.account;
    }
}

/** Throws NoAnswer when the RPC doesn't answer: offline, timeout, 5xx, 429, or not JSON. */
export function rpcServer(rpcUrl) {
    const server = new AdminRpcServer(rpcUrl, {
        allowHttp: rpcUrl.startsWith("http://"),
        timeout: RPC_TIMEOUT_MS,
    });
    server.httpClient.interceptors.response.use(
        (response) => {
            // No body: a mid-stream timeout or a page that isn't the RPC.
            if (typeof response.data !== "object" || response.data === null)
                throw new NoAnswer(response);
            return response;
        },
        (err) => {
            const status = err?.response?.status;
            if (!err?.isAxiosError || (status < 500 && status !== 429))
                throw err;
            throw new NoAnswer(err);
        },
    );
    return server;
}

/** Reads the network's `max_entry_ttl`: an entry lives at most that many ledgers, counting the current one. */
export async function maxEntryTtl(server) {
    const key = xdr.LedgerKey.configSetting(
        new xdr.LedgerKeyConfigSetting({
            configSettingId: xdr.ConfigSettingId.configSettingStateArchival,
        }),
    );
    const { val } = await server.getLedgerEntry(key);
    return val.configSetting.stateArchivalSettings.maxEntryTtl;
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
        throw new Error("the envelope is a fee bump, not an admin call");
    }
    // The card shows only the time bound. A minimum-sequence condition would keep a
    // signed envelope valid past later admin calls; a bound with no end never expires.
    if (
        tx.toEnvelope().value.tx.cond.type !== "precondTime" ||
        Number(tx.timeBounds.maxTime) === 0
    ) {
        throw new Error(
            "the envelope carries conditions other than a time bound",
        );
    }
    const [operation, ...others] = tx.operations;
    const call = operation?.func?.invokeContract;
    // A pasted envelope could hide a second, undescribed operation.
    if (others.length > 0 || !call) {
        throw new Error(
            "the envelope holds something other than one contract call",
        );
    }
    // The signatures cover every source-account entry, so another call's entry would
    // run undescribed, and one needing another account's signature would fail.
    const describedCall = ({ credentials, rootInvocation }) =>
        credentials.type === "sorobanCredentialsSourceAccount" &&
        rootInvocation.function.contractFn?.equals(call) &&
        rootInvocation.subInvocations.length === 0;
    if (
        (operation.source && operation.source !== tx.source) ||
        !operation.auth.every(describedCall)
    ) {
        throw new Error(
            "the envelope authorizes something other than this call by its source",
        );
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
 * Returns the card's line for a `claim_fees` call: the amount, when `amount`
 * formats it, beside its base units, and whether it pays the admin account
 * that signs it.
 */
export function claimLine({ source, args: [to, claimed] }, amount) {
    const payee =
        to === source
            ? "the admin account (Source)"
            : `${to}, not the admin account`;
    return `Claim${
        amount
            ? ` ${amount(
                  claimed,
              )} (${claimed} in the token's smallest unit, as Arguments and Varial show it)`
            : ""
    } to ${payee}`;
}

/** Returns the number of signatures an envelope carries. */
export function signatureCount(xdr, networkPassphrase) {
    return TransactionBuilder.fromXdr(xdr, networkPassphrase).signatures.length;
}

/** Reports whether an envelope already carries a signature by `publicKey`. */
export function signedBy(xdr, networkPassphrase, publicKey) {
    const tx = TransactionBuilder.fromXdr(xdr, networkPassphrase);
    const key = Keypair.fromPublicKey(publicKey);
    return tx.signatures.some(({ signature }) =>
        key.verify(tx.hash(), signature),
    );
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
    const weights = new Map(
        account.signers.map(({ key, weight }) => [
            SignerKey.encodeSignerKey(key),
            weight,
        ]),
    );
    weights.set(
        StrKey.encodeEd25519PublicKey(account.accountId.ed25519.value),
        master,
    );
    return { threshold: Math.max(medium, 1), weights };
}

/**
 * Returns why `address` must not sign, or `null` when its signature counts.
 * An unused signature fails the transaction and cannot be removed: a
 * non-signer's, one past the threshold, or a signer's second.
 */
export function signRefusal(
    { threshold, weights },
    xdr,
    networkPassphrase,
    address,
) {
    if (!(weights.get(address) > 0)) {
        return `${address} does not sign for ${
            TransactionBuilder.fromXdr(xdr, networkPassphrase).source
        }`;
    }
    if (signedWeight({ weights }, xdr, networkPassphrase) >= threshold) {
        return "The envelope already carries the signatures it needs. Submit it.";
    }
    if (signedBy(xdr, networkPassphrase, address)) {
        return "This account has already signed the envelope";
    }
    return null;
}

/**
 * Lists each key of weight above 0 with whether the envelope carries its
 * signature, or `null` for a key that is not an ed25519 key, whose signature
 * cannot be matched to it.
 *
 * @returns {Array<{key: string, signed: boolean|null}>}
 */
export function signerStatus({ weights }, xdr, networkPassphrase) {
    return [...weights]
        .filter(([, weight]) => weight > 0)
        .map(([key]) => ({
            key,
            signed: StrKey.isValidEd25519PublicKey(key)
                ? signedBy(xdr, networkPassphrase, key)
                : null,
        }));
}

/** Returns the summed weight of the keys whose signatures an envelope carries. */
export function signedWeight(rule, xdr, networkPassphrase) {
    return signerStatus(rule, xdr, networkPassphrase).reduce(
        (sum, { key, signed }) => sum + (signed ? rule.weights.get(key) : 0),
        0,
    );
}

/**
 * Returns `pageUrl` carrying the envelope in its fragment, which the browser
 * never sends to a server.
 */
export const adminTxLink = (pageUrl, xdr) =>
    `${pageUrl}#tx=${encodeURIComponent(xdr)}`;

/** Returns the envelope in a fragment `adminTxLink` wrote, or `''`. */
export const adminTxFromHash = (hash) =>
    new URLSearchParams(hash.slice(1)).get("tx") ?? "";

/**
 * Returns why `value` cannot be proposed as a contract's new admin, or `null`.
 * No message repeats `value`, so a secret key pasted by mistake stays out of a toast.
 */
export function newAdminRefusal(value, { admin, pending }) {
    if (!value) return "The new admin's address is required";
    if (
        !StrKey.isValidEd25519PublicKey(value) &&
        !StrKey.isValidContract(value)
    ) {
        return "The new admin must be an account address (G...) or a contract address (C...)";
    }
    if (value === admin) return "The new admin is already the contract's admin";
    if (value === pending) return "The new admin is already the pending admin";
    return null;
}

/**
 * Lists how an admin account breaks the custody rules `verify-deployment.sh`
 * checks, one problem per rule broken, or `[]`.
 *
 * @param {xdr.AccountEntry} account
 * @returns {string[]}
 */
export function custodyProblems(account) {
    const [master, low, medium, high] = account.thresholds.value;
    const { signers } = account;
    const problems = [];
    if (master !== 0) problems.push(`its own key has weight ${master}, not 0`);
    if (low !== high || medium !== high)
        problems.push(
            `its low, medium, and high thresholds are ${low}, ${medium}, and ${high}, not equal`,
        );
    if (high < 2) problems.push(`its threshold is ${high}, below 2`);
    if (high > signers.length)
        problems.push(
            `its threshold is ${high}, above its ${signers.length} signers`,
        );
    for (const { key, weight } of signers) {
        const signer = SignerKey.encodeSignerKey(key);
        if (!StrKey.isValidEd25519PublicKey(signer))
            problems.push(`signer ${signer} is not an ed25519 key`);
        if (weight !== 1)
            problems.push(`signer ${signer} has weight ${weight}, not 1`);
    }
    return problems;
}

/**
 * Formats a `host_fn_failed` diagnostic event's error the way a failed simulation
 * does, for example `Error(Contract, #20)`, or returns `''`. A failed sent
 * transaction reports its error only in these events.
 */
export function hostError(events = []) {
    const topics = events
        .map(({ event }) => event.body.v0.topics)
        .find(([name]) => scValToNative(name) === "host_fn_failed");
    if (!topics) return "";
    const { type, contractCode, code } = topics[1].error;
    const detail =
        type === "sceContract"
            ? `#${contractCode}`
            : code.name.slice("scec".length);
    return `Error(${type.slice("sce".length)}, ${detail})`;
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
export async function submitAdminCall({
    rpcUrl,
    networkPassphrase,
    xdr,
    server = rpcServer(rpcUrl),
}) {
    const sent = await server.sendTransaction(
        TransactionBuilder.fromXdr(xdr, networkPassphrase),
    );
    // The network answers `DUPLICATE` to this envelope sent again, and
    // `TRY_AGAIN_LATER` to a co-signer's copy carrying other signatures.
    const landed = ["PENDING", "DUPLICATE", "TRY_AGAIN_LATER"].includes(
        sent.status,
    )
        ? await server.pollTransaction(sent.hash, { attempts: 30 })
        : await server.getTransaction(sent.hash);
    if (landed.status === "SUCCESS") return landed;
    if (sent.status !== "PENDING" && landed.status === "NOT_FOUND") {
        throw new Error(
            `transaction ${sent.status}: ${
                sent.errorResult?.result.type ?? ""
            } ${hostError(sent.diagnosticEvents)}`,
        );
    }
    throw landedFailure(sent.hash, landed);
}

const landedFailure = (hash, landed) =>
    new Error(
        `transaction ${hash} ${landed.status}: ${
            landed.resultXdr?.result.type ?? ""
        } ${hostError(landed.diagnosticEventsXdr)}`,
    );

const SEQUENCE_USED =
    "This call is out of date: the admin account sent another transaction first. Build it again if it's still needed.";
const TIME_BOUND_PASSED = "This call has expired. Build it again.";

/**
 * Why the card's call can't land any more, or null. A co-signer may have sent
 * it already, or the contract may refuse it now, as it refuses a claim that
 * another claim has spent.
 */
export async function deadCall({
    server,
    envelope,
    networkPassphrase,
    account,
    now,
    kind,
}) {
    const tx = TransactionBuilder.fromXdr(envelope, networkPassphrase);
    // Sequence number not used yet.
    if (BigInt(account.seqNum) < BigInt(tx.sequence)) {
        if (Number(tx.timeBounds.maxTime) * 1000 <= now)
            return { reason: TIME_BOUND_PASSED, landed: false };
        const simulation = await server.simulateTransaction(tx);
        if (!rpc.Api.isSimulationError(simulation)) return null;
        const why = explainFailure(simulation.error, kind);
        // An unnamed refusal is simulation output, unfit for the card.
        if (why !== simulation.error)
            return {
                reason: `This call would fail if sent. ${why}`,
                landed: false,
            };
        console.error(simulation.error);
        return {
            reason: "This call would fail if sent, and this page can't tell why. The browser console shows the network's answer. Check the contract before building the call again.",
            landed: false,
        };
    }
    const hash = hex(tx.hash());
    // About two ledger closes: a load-balanced node can lag the account read.
    const landed = await server.pollTransaction(hash, { attempts: 10 });
    if (landed.status === "SUCCESS")
        return { reason: "This call already went through.", landed: true };
    if (landed.status === "FAILED")
        return {
            reason: `This call went through and failed: ${explainFailure(
                landedFailure(hash, landed),
                kind,
            )}`,
            landed: false,
        };
    return { reason: SEQUENCE_USED, landed: false };
}

export const repointsTo = (call, { pool, method, tree, source }) =>
    call.contract === pool &&
    call.method === method &&
    call.args[0] === tree &&
    (source === undefined || call.source === source);

// Tested in order: `tx_bad_auth_extra` before `tx_bad_auth`, which also matches it.
const NETWORK_REFUSALS = [
    [
        /tx_?bad_?auth_?extra/i,
        "The transaction carries a signature it does not use: more than the threshold needs, one signer twice, or a key that is not a signer. Build the call again and collect the threshold's signatures, one from each signer.",
    ],
    [
        /tx_?bad_?auth/i,
        "The transaction lacks signatures. Collect more from the admin account's signers.",
    ],
    [/tx_?bad_?seq/i, SEQUENCE_USED],
    [/tx_?too_?late/i, TIME_BOUND_PASSED],
    [
        /TRY_AGAIN_LATER|NOT_FOUND|DUPLICATE/,
        "The network has not confirmed the transaction yet. Check the contract before building the call again.",
    ],
    [
        /Error\(Auth, InvalidAction\)/,
        "The transaction's source is not the contract's admin.",
    ],
    [
        /Error\(Budget, ExceededLimit\)/,
        "The call needs more resources than one transaction allows. For a blocklist insert, add fewer keys at a time.",
    ],
    [
        /tx_?insufficient_?balance/i,
        "The paying account doesn't have enough XLM for the fee. Add some and try again.",
    ],
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
    if (kind === "pool" && code >= 18 && CONTRACT_ERRORS.pool[code])
        return CONTRACT_ERRORS.pool[code];
    // Codes differ by contract: #6 is an allowlist's `NoPendingAdmin` but a blocklist's `Overflow`.
    return (
        {
            "asp-membership": CONTRACT_ERRORS.aspMembership,
            "asp-non-membership": CONTRACT_ERRORS.aspNonMembership,
        }[kind]?.[code] ?? message
    );
}
