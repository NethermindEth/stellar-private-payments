import xdr from "./xdr.js";
import { Keypair } from "./keypair.js";
type BufferLike = ArrayBuffer | Buffer | Uint8Array;
/**
 * A callback for signing an XDR structure representing all of the details
 * necessary to authorize an invocation tree.
 *
 * @param preimage - the entire authorization envelope whose hash you should
 *    sign, so that you can inspect the entire structure if necessary (rather
 *    than blindly signing a hash)
 *
 * @returns the signature of the raw payload (which is the sha256 hash of the
 *    preimage bytes, so `hash(preimage.toXDR())`) either naked, implying it is
 *    signed by the key corresponding to the public key in the entry you pass to
 *    {@link authorizeEntry} (decipherable from its
 *    `credentials().address().address()`), or alongside an explicit `publicKey`.
 */
export type SigningCallback = (preimage: xdr.HashIdPreimage) => Promise<BufferLike | {
    signature: BufferLike;
    publicKey: string;
}>;
/**
 * Actually authorizes an existing authorization entry using the given
 * credentials and expiration details, returning a signed copy.
 *
 * This "fills out" the authorization entry with a signature, indicating to the
 * {@link Operation.invokeHostFunction} its attached to that:
 *   - a particular identity (i.e. signing {@link Keypair} or other signer)
 *   - approving the execution of an invocation tree (i.e. a simulation-acquired
 *     {@link xdr.SorobanAuthorizedInvocation} or otherwise built)
 *   - on a particular network (uniquely identified by its passphrase, see
 *     {@link Networks})
 *   - until a particular ledger sequence is reached.
 *
 * This one lets you pass either a {@link Keypair} (or, more accurately,
 * anything with a `sign(Buffer): Buffer` method) or a callback function (see
 * {@link SigningCallback}) to handle signing the envelope hash.
 *
 * @param entry - an unsigned authorization entry
 * @param signer - either a {@link Keypair} instance or a function which takes a
 *    {@link xdr.HashIdPreimageSorobanAuthorization} input payload and returns
 *    EITHER
 *
 *      (a) an object containing a `signature` of the hash of the raw payload
 *          bytes as a Buffer-like and a `publicKey` string representing who just
 *          created this signature, or
 *      (b) just the naked signature of the hash of the raw payload bytes (where
 *          the signing key is implied to be the address in the `entry`).
 *
 *    The latter option (b) is JUST for backwards compatibility and will be
 *    removed in the future.
 * @param validUntilLedgerSeq - the (exclusive) future ledger sequence number
 *    until which this authorization entry should be valid (if
 *    `currentLedgerSeq==validUntil`, this is expired)
 * @param networkPassphrase - the network passphrase is incorporated into the
 *    signature (see {@link Networks} for options)
 *
 * If using the `SigningCallback` variation, the signer is assumed to be
 * the entry's credential address unless you use the variant that returns
 * the object.
 *
 * @param forAddress - which credential node the signature should be written
 *    to. Only relevant for `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES`, where
 *    a single entry can be signed by the top-level account and/or any of its
 *    (possibly nested) delegates. Per CAP-71-01 every one of these signers
 *    signs the *same* payload (bound to the top-level address), so the
 *    signature produced here is written to whichever node(s) carry
 *    `forAddress`. When omitted, the signature is written to the top-level
 *    credentials, which preserves the behavior for `SOROBAN_CREDENTIALS_ADDRESS`
 *    / `SOROBAN_CREDENTIALS_ADDRESS_V2` and for accounts whose signing key
 *    differs from the credential address (e.g. multisig).
 *
 * @see authorizeInvocation
 * @example
 * ```ts
 * import {
 *   SorobanRpc,
 *   Transaction,
 *   Networks,
 *   authorizeEntry
 * } from '@stellar/stellar-sdk';
 *
 * // Assume signPayloadCallback is a well-formed signing callback.
 * //
 * // It might, for example, pop up a modal from a browser extension, send the
 * // transaction to a third-party service for signing, or just do simple
 * // signing via Keypair like it does here:
 * function signPayloadCallback(payload) {
 *    return signer.sign(hash(payload.toXDR()));
 * }
 *
 * function multiPartyAuth(
 *    server: SorobanRpc.Server,
 *    // assume this involves multi-party auth
 *    tx: Transaction,
 * ) {
 *    return server
 *      .simulateTransaction(tx)
 *      .then((simResult) => {
 *          tx.operations[0].auth.map(entry =>
 *            authorizeEntry(
 *              entry,
 *              signPayloadCallback,
 *              currentLedger + 1000,
 *              Networks.TESTNET)
 *          );
 *
 *          return server.prepareTransaction(tx, simResult);
 *      })
 *      .then((preppedTx) => {
 *        preppedTx.sign(source);
 *        return server.sendTransaction(preppedTx);
 *      });
 * }
 * ```
 */
export declare function authorizeEntry(entry: xdr.SorobanAuthorizationEntry, signer: Keypair | SigningCallback, validUntilLedgerSeq: number, networkPassphrase: string, forAddress?: string): Promise<xdr.SorobanAuthorizationEntry>;
export interface AuthorizeInvocationParams {
    signer: Keypair | SigningCallback;
    validUntilLedgerSeq: number;
    invocation: xdr.SorobanAuthorizedInvocation;
    networkPassphrase: string;
    publicKey?: string;
    /**
     * Build `SOROBAN_CREDENTIALS_ADDRESS_V2` (CAP-71) credentials instead of the
     * legacy `SOROBAN_CREDENTIALS_ADDRESS`. V2 credentials bind the address into
     * the signed payload but are only valid on networks that have activated
     * CAP-71, so leave this off until the activation vote passes for your target
     * network. The default flips to `true` once V2 becomes mandatory.
     * @defaultValue false
     */
    authV2?: boolean;
}
/**
 * This builds an entry from scratch, allowing you to express authorization as a
 * function of:
 *   - a particular identity (i.e. signing {@link Keypair} or other signer)
 *   - approving the execution of an invocation tree (i.e. a simulation-acquired
 *     {@link xdr.SorobanAuthorizedInvocation} or otherwise built)
 *   - on a particular network (uniquely identified by its passphrase, see
 *     {@link Networks})
 *   - until a particular ledger sequence is reached.
 *
 * This is in contrast to {@link authorizeEntry}, which signs an existing entry.
 *
 * @param params - the parameters for building and signing the authorization
 *   - `signer`: either a {@link Keypair} instance (or anything with a
 *    `.sign(buf): Buffer-like` method) or a function which takes a payload (a
 *    {@link xdr.HashIdPreimageSorobanAuthorization} instance) input and returns
 *    the signature of the hash of the raw payload bytes (where the signing key
 *    should correspond to the address in the `entry`)
 *   - `validUntilLedgerSeq`: the (exclusive) future ledger sequence
 *    number until which this authorization entry should be valid (if
 *    `currentLedgerSeq==validUntilLedgerSeq`, this is expired)
 *   - `invocation`: the invocation tree that we're authorizing
 *    (likely, this comes from transaction simulation)
 *   - `networkPassphrase`: the network passphrase is incorporated into
 *    the signature (see {@link Networks} for options)
 *   - `publicKey`: the public identity of the signer (when providing a
 *    {@link Keypair} to `signer`, this can be omitted, as it just uses
 *    {@link Keypair.publicKey})
 *   - `authV2`: build `SOROBAN_CREDENTIALS_ADDRESS_V2` (CAP-71) credentials
 *    rather than the legacy `SOROBAN_CREDENTIALS_ADDRESS`. Defaults to `false`;
 *    only enable it for networks that have activated CAP-71.
 *
 * @see authorizeEntry
 */
export declare function authorizeInvocation(params: AuthorizeInvocationParams): Promise<xdr.SorobanAuthorizationEntry>;
/**
 * Builds the {@link xdr.HashIdPreimage} whose hash a signer must sign to
 * authorize `entry`. This is the low-level signature payload used by
 * {@link authorizeEntry}, exposed for callers that drive signing themselves —
 * most notably for `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES`, where the
 * client (not simulation) decides which delegates sign and how.
 *
 * For `SOROBAN_CREDENTIALS_ADDRESS` this is the legacy, non-address-bound
 * `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` preimage. For `SOROBAN_CREDENTIALS_ADDRESS_V2`
 * and `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` it is the address-bound
 * `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` preimage (CAP-71). For the
 * delegates variant this single payload — bound to the *top-level* address — is
 * what the top-level account and every (nested) delegate each sign.
 *
 * To get the raw bytes to sign, hash the XDR: `hash(preimage.toXDR())`.
 *
 * @param entry - the authorization entry to build the payload for
 * @param validUntilLedgerSeq - the expiration ledger committed into the payload
 *    (must match the `signatureExpirationLedger` on the credentials you submit)
 * @param networkPassphrase - the network passphrase mixed into the payload
 * @throws `Error` if `entry` carries source-account or otherwise non-address
 *    credentials
 */
export declare function buildAuthorizationEntryPreimage(entry: xdr.SorobanAuthorizationEntry, validUntilLedgerSeq: number, networkPassphrase: string): xdr.HashIdPreimage;
/**
 * A delegate signer to attach to a
 * `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` entry via
 * {@link buildWithDelegatesEntry}.
 */
export interface DelegateSignature {
    /** the delegate's address (`G…` account or `C…` contract). */
    address: string;
    /**
     * the delegate's signature value. Defaults to a `scvVoid` placeholder, which
     * you can fill afterwards with {@link authorizeEntry} (passing this address
     * as `forAddress`) or by editing the entry directly.
     */
    signature?: xdr.ScVal;
    /** signers this delegate in turn delegates to (recursive). */
    nestedDelegates?: DelegateSignature[];
}
/** Parameters for {@link buildWithDelegatesEntry}. */
export interface BuildWithDelegatesParams {
    /**
     * an existing `SOROBAN_CREDENTIALS_ADDRESS` or
     * `SOROBAN_CREDENTIALS_ADDRESS_V2` entry — typically one returned by
     * simulation — whose address credentials should be wrapped.
     */
    entry: xdr.SorobanAuthorizationEntry;
    /** the expiration ledger sequence stored on the top-level credentials. */
    validUntilLedgerSeq: number;
    /** the delegate signers to attach. */
    delegates: DelegateSignature[];
    /**
     * the top-level account's signature. Defaults to `scvVoid`, which is valid
     * for accounts that authorize purely via delegated signers (CAP-71-01).
     */
    signature?: xdr.ScVal;
}
/**
 * Builds a `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` authorization entry by
 * wrapping the address credentials of an existing `ADDRESS`/`ADDRESS_V2` entry
 * (e.g. one returned by simulation) together with a caller-provided set of
 * delegate signers.
 *
 * Simulation never emits the delegates variant on its own — which accounts use
 * delegated authentication is account-specific policy known only to the client
 * (much like a multisig policy). This helper just assembles the wrapper XDR;
 * you supply the delegate tree (addresses and, optionally, signatures). To
 * produce the signatures, build the shared payload with
 * {@link buildAuthorizationEntryPreimage} on the returned entry and sign it,
 * or fill each node afterwards with {@link authorizeEntry} (passing the
 * signer's address as `forAddress`).
 *
 * Each delegates array (the top-level set and every `nestedDelegates`) is
 * sorted by address in ascending order, and duplicate addresses within an array
 * are rejected, as the protocol requires (CAP-71-01) — otherwise the host
 * rejects the entry.
 *
 * @param params - see {@link BuildWithDelegatesParams}
 * @throws `Error` if `entry` is not an `ADDRESS`/`ADDRESS_V2` entry, or if any
 *    delegates array contains a duplicate address.
 */
export declare function buildWithDelegatesEntry(params: BuildWithDelegatesParams): xdr.SorobanAuthorizationEntry;
/**
 * Internal helper — intentionally NOT re-exported from `base/index.js`, so it
 * is not part of the public SDK API. Shared with the contract package, which
 * imports it directly from this module. If a public need arises, add it to the
 * explicit auth re-exports in `base/index.ts`.
 *
 * Extracts the {@link xdr.SorobanAddressCredentials} from any address-based
 * Soroban credential, regardless of which credential type variant is used.
 *
 * This unifies access across `SOROBAN_CREDENTIALS_ADDRESS`,
 * `SOROBAN_CREDENTIALS_ADDRESS_V2` (which carries identical fields but binds
 * the address into the signature payload), and
 * `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (which wraps the same address
 * credentials alongside a set of delegate signatures).
 *
 * @param credentials - the credentials to inspect
 * @returns the inner address credentials, or `null` for source-account
 *    credentials (which carry no address payload)
 */
export declare function getAddressCredentials(credentials: xdr.SorobanCredentials): xdr.SorobanAddressCredentials | null;
export {};
