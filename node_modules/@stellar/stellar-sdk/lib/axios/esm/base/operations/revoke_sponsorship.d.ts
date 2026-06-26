import xdr from "../xdr.js";
import { RevokeAccountSponsorshipOpts, RevokeAccountSponsorshipResult, RevokeTrustlineSponsorshipOpts, RevokeTrustlineSponsorshipResult, RevokeOfferSponsorshipOpts, RevokeOfferSponsorshipResult, RevokeDataSponsorshipOpts, RevokeDataSponsorshipResult, RevokeClaimableBalanceSponsorshipOpts, RevokeClaimableBalanceSponsorshipResult, RevokeLiquidityPoolSponsorshipOpts, RevokeLiquidityPoolSponsorshipResult, RevokeSignerSponsorshipOpts, RevokeSignerSponsorshipResult } from "./types.js";
/**
 * Create a "revoke sponsorship" operation for an account.
 *
 * @param opts - Options object
 *   - `account`: The sponsored account ID.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeAccountSponsorship({
 *   account: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7'
 * });
 * ```
 */
export declare function revokeAccountSponsorship(opts?: RevokeAccountSponsorshipOpts): xdr.Operation<RevokeAccountSponsorshipResult>;
/**
 * Create a "revoke sponsorship" operation for a trustline.
 *
 * @param opts - Options object
 *   - `account`: The account ID which owns the trustline.
 *   - `asset`: The trustline asset.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeTrustlineSponsorship({
 *   account: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7',
 *   asset: new StellarBase.LiquidityPoolId(
 *     'USDUSD',
 *     'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7'
 *   )
 * });
 * ```
 */
export declare function revokeTrustlineSponsorship(opts?: RevokeTrustlineSponsorshipOpts): xdr.Operation<RevokeTrustlineSponsorshipResult>;
/**
 * Create a "revoke sponsorship" operation for an offer.
 *
 * @param opts - Options object
 *   - `seller`: The account ID which created the offer.
 *   - `offerId`: The offer ID.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeOfferSponsorship({
 *   seller: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7',
 *   offerId: '1234'
 * });
 * ```
 */
export declare function revokeOfferSponsorship(opts?: RevokeOfferSponsorshipOpts): xdr.Operation<RevokeOfferSponsorshipResult>;
/**
 * Create a "revoke sponsorship" operation for a data entry.
 *
 * @param opts - Options object
 *   - `account`: The account ID which owns the data entry.
 *   - `name`: The name of the data entry.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeDataSponsorship({
 *   account: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7',
 *   name: 'foo'
 * });
 * ```
 */
export declare function revokeDataSponsorship(opts?: RevokeDataSponsorshipOpts): xdr.Operation<RevokeDataSponsorshipResult>;
/**
 * Create a "revoke sponsorship" operation for a claimable balance.
 *
 * @param opts - Options object
 *   - `balanceId`: The sponsored claimable balance ID.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeClaimableBalanceSponsorship({
 *   balanceId: '00000000da0d57da7d4850e7fc10d2a9d0ebc731f7afb40574c03395b17d49149b91f5be',
 * });
 * ```
 */
export declare function revokeClaimableBalanceSponsorship(opts?: RevokeClaimableBalanceSponsorshipOpts): xdr.Operation<RevokeClaimableBalanceSponsorshipResult>;
/**
 * Creates a "revoke sponsorship" operation for a liquidity pool.
 *
 * @param opts - Options object.
 *   - `liquidityPoolId`: The sponsored liquidity pool ID in 'hex' string.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeLiquidityPoolSponsorship({
 *   liquidityPoolId: 'dd7b1ab831c273310ddbec6f97870aa83c2fbd78ce22aded37ecbf4f3380fac7',
 * });
 * ```
 */
export declare function revokeLiquidityPoolSponsorship(opts?: RevokeLiquidityPoolSponsorshipOpts): xdr.Operation<RevokeLiquidityPoolSponsorshipResult>;
/**
 * Create a "revoke sponsorship" operation for a signer.
 *
 * @param opts - Options object
 *   - `account`: The account ID where the signer sponsorship is being removed from.
 *   - `signer`: The signer whose sponsorship is being removed. Exactly one of the following must be set:
 *   - `signer.ed25519PublicKey`: (optional) The ed25519 public key of the signer.
 *   - `signer.sha256Hash`: (optional) sha256 hash (Buffer or hex string).
 *   - `signer.preAuthTx`: (optional) Hash (Buffer or hex string) of transaction.
 *   - `signer.ed25519SignedPayload`: (optional) Signed payload signer (StrKey P... address).
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.revokeSignerSponsorship({
 *   account: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7',
 *   signer: {
 *     ed25519PublicKey: 'GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ'
 *   }
 * })
 * ```
 */
export declare function revokeSignerSponsorship(opts?: RevokeSignerSponsorshipOpts): xdr.Operation<RevokeSignerSponsorshipResult>;
