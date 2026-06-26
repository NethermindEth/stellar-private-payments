import xdr from "../xdr.js";
import { ClawbackClaimableBalanceResult, ClawbackClaimableBalanceOpts } from "./types.js";
/**
 * Creates a clawback operation for a claimable balance.
 *
 * @param opts - Options object
 *   - `balanceId`: The claimable balance ID to be clawed back.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.clawbackClaimableBalance({
 *   balanceId: '00000000da0d57da7d4850e7fc10d2a9d0ebc731f7afb40574c03395b17d49149b91f5be',
 * });
 * ```
 *
 * @see https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md#clawback-claimable-balance-operation
 */
export declare function clawbackClaimableBalance(opts?: ClawbackClaimableBalanceOpts): xdr.Operation<ClawbackClaimableBalanceResult>;
