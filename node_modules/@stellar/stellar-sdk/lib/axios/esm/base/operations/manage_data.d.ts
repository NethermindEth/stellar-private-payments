import xdr from "../xdr.js";
import { ManageDataResult, ManageDataOpts } from "./types.js";
/**
 * This operation adds data entry to the ledger.
 * @param opts - Options object
 *   - `name`: The name of the data entry.
 *   - `value`: The value of the data entry.
 *   - `source`: The optional source account.
 */
export declare function manageData(opts: ManageDataOpts): xdr.Operation<ManageDataResult>;
