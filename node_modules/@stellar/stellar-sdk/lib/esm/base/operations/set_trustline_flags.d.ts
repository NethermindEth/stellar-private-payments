import xdr from "../xdr.js";
import { SetTrustLineFlagsOpts, SetTrustLineFlagsResult } from "./types.js";
/**
 * Creates a trustline flag configuring operation.
 *
 * For the flags, set them to true to enable them and false to disable them. Any
 * unmodified operations will be marked `undefined` in the result.
 *
 * Note that you can only **clear** the clawbackEnabled flag set; it must be set
 * account-wide via operations.SetOptions (setting
 * xdr.AccountFlags.clawbackEnabled).
 *
 *
 * @param opts - Options object
 *   - `trustor`: the account whose trustline this is
 *   - `asset`: the asset on the trustline
 *   - `flags`: the set of flags to modify
 *   - `flags.authorized`: authorize account to perform
 *     transactions with its credit
 *   - `flags.authorizedToMaintainLiabilities`: authorize
 *     account to maintain and reduce liabilities for its credit
 *   - `flags.clawbackEnabled`: stop claimable balances on
 *     this trustlines from having clawbacks enabled (this flag can only be set
 *     to false!)
 *   - `source`: The source account for the operation.
 *                                 Defaults to the transaction's source account.
 *
 * @see https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md#set-trustline-flags-operation
 * @see https://developers.stellar.org/docs/start/list-of-operations/#set-options
 */
export declare function setTrustLineFlags(opts: SetTrustLineFlagsOpts): xdr.Operation<SetTrustLineFlagsResult>;
