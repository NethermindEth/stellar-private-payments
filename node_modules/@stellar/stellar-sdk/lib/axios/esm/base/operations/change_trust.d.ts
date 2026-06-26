import xdr from "../xdr.js";
import { ChangeTrustResult, ChangeTrustOpts } from "./types.js";
/**
 * A "change trust" operation adds, removes, or updates a trust line for a
 * given asset from the source account to another.
 *
 * @param opts - Options object
 *   - `asset`: The asset for the trust line.
 *   - `limit`: The limit for the asset, defaults to max int64.
 *                     If the limit is set to "0" it deletes the trustline.
 *   - `source`: The source account (defaults to transaction source).
 */
export declare function changeTrust(opts: ChangeTrustOpts): xdr.Operation<ChangeTrustResult>;
