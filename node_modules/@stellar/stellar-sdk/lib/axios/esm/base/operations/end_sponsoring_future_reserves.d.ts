import xdr from "../xdr.js";
import { EndSponsoringFutureReservesResult, EndSponsoringFutureReservesOpts } from "./types.js";
/**
 * Create an "end sponsoring future reserves" operation.
 * @param opts - Options object
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.endSponsoringFutureReserves();
 * ```
 *
 */
export declare function endSponsoringFutureReserves(opts?: EndSponsoringFutureReservesOpts): xdr.Operation<EndSponsoringFutureReservesResult>;
