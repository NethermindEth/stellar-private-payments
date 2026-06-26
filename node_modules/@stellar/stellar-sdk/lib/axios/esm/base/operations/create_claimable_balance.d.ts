import xdr from "../xdr.js";
import { CreateClaimableBalanceResult, CreateClaimableBalanceOpts } from "./types.js";
/**
 * Create a new claimable balance operation.
 *
 *
 * @param opts - Options object
 *   - `asset`: The asset for the claimable balance.
 *   - `amount`: Amount.
 *   - `claimants`: An array of Claimants
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 *
 * @example
 * ```ts
 * const asset = new Asset(
 *   'USD',
 *   'GDGU5OAPHNPU5UCLE5RDJHG7PXZFQYWKCFOEXSXNMR6KRQRI5T6XXCD7'
 * );
 * const amount = '100.0000000';
 * const claimants = [
 *   new Claimant(
 *     'GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ',
 *      Claimant.predicateBeforeAbsoluteTime("4102444800000")
 *   )
 * ];
 *
 * const op = Operation.createClaimableBalance({
 *   asset,
 *   amount,
 *   claimants
 * });
 * ```
 */
export declare function createClaimableBalance(opts: CreateClaimableBalanceOpts): xdr.Operation<CreateClaimableBalanceResult>;
