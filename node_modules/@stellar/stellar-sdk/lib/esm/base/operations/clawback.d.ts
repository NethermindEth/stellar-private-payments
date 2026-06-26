import xdr from "../xdr.js";
import { ClawbackOpts, ClawbackResult } from "./types.js";
/**
 * Creates a clawback operation.
 *
 *
 * @param opts - Options object
 *   - `asset`: The asset being clawed back.
 *   - `amount`: The amount of the asset to claw back.
 *   - `from`: The public key of the (optionally-muxed)
 *     account to claw back from.
 *   - `source`: The source account for the operation.
 *     Defaults to the transaction's source account.
 *
 * @see https://github.com/stellar/stellar-protocol/blob/master/core/cap-0035.md#clawback-operation
 */
export declare function clawback(opts: ClawbackOpts): xdr.Operation<ClawbackResult>;
