import xdr from "../xdr.js";
import { BeginSponsoringFutureReservesResult, BeginSponsoringFutureReservesOpts } from "./types.js";
/**
 * Create a "begin sponsoring future reserves" operation.
 * @param opts - Options object
 *   - `sponsoredId`: The sponsored account id.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const op = Operation.beginSponsoringFutureReserves({
 *   sponsoredId: 'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7'
 * });
 * ```
 *
 */
export declare function beginSponsoringFutureReserves(opts: BeginSponsoringFutureReservesOpts): xdr.Operation<BeginSponsoringFutureReservesResult>;
