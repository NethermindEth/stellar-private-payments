import xdr from "../xdr.js";
import { InflationOpts, InflationResult } from "./types.js";
/**
 * This operation generates the inflation.
 * @param opts - Options object
 *   - `source`: The optional source account.
 */
export declare function inflation(opts?: InflationOpts): xdr.Operation<InflationResult>;
