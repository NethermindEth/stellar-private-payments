import xdr from "../xdr.js";
import { ClaimClaimableBalanceResult, ClaimClaimableBalanceOpts } from "./types.js";
/**
 * Create a new claim claimable balance operation.
 * @param opts - Options object
 *   - `balanceId`: The claimable balance id to be claimed.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.claimClaimableBalance({
 *   balanceId: '00000000da0d57da7d4850e7fc10d2a9d0ebc731f7afb40574c03395b17d49149b91f5be',
 * });
 * ```
 */
export declare function claimClaimableBalance(opts?: ClaimClaimableBalanceOpts): xdr.Operation<ClaimClaimableBalanceResult>;
/**
 * Validates that a claimable balance ID has the expected format.
 *
 * @param balanceId - The claimable balance ID to validate.
 */
export declare function validateClaimableBalanceId(balanceId: unknown): void;
