import xdr from "../xdr.js";
import { RestoreFootprintResult, RestoreFootprintOpts } from "./types.js";
/**
 * Builds an operation to restore the archived ledger entries specified
 * by the ledger keys.
 *
 * The ledger keys to restore are specified separately from the operation
 * in read-write footprint of the transaction.
 *
 * It takes no parameters because the relevant footprint is derived from the
 * transaction itself. See {@link TransactionBuilder}'s `opts.sorobanData`
 * parameter (or {@link TransactionBuilder.setSorobanData}), which is a
 * {@link xdr.SorobanTransactionData} instance that contains fee data & resource
 * usage as part of {@link xdr.SorobanTransactionData}.
 *
 *
 * @param opts - an optional set of parameters
 *   - `source`: an optional source account
 */
export declare function restoreFootprint(opts?: RestoreFootprintOpts): xdr.Operation<RestoreFootprintResult>;
