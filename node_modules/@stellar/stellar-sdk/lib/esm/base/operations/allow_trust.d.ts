import xdr from "../xdr.js";
import { AllowTrustResult, AllowTrustOpts } from "./types.js";
/**
 * @deprecated since v5.0
 *
 * An "allow trust" operation authorizes another account to hold your
 * account's credit for a given asset.
 *
 * @param opts - Options object
 *   - `trustor`: The trusting account (the one being authorized)
 *   - `assetCode`: The asset code being authorized.
 *   - `authorize`: `1` to authorize, `2` to authorize to maintain liabilities, and `0` to deauthorize.
 *   - `source`: The source account (defaults to transaction source).
 */
export declare function allowTrust(opts: AllowTrustOpts): xdr.Operation<AllowTrustResult>;
