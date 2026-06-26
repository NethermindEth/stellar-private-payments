import xdr from "../xdr.js";
import { LiquidityPoolWithdrawResult, LiquidityPoolWithdrawOpts } from "./types.js";
/**
 * Creates a liquidity pool withdraw operation.
 *
 * @see https://developers.stellar.org/docs/start/list-of-operations/#liquidity-pool-withdraw
 *
 * @param opts - Options object
 *   - `liquidityPoolId`: The liquidity pool ID.
 *   - `amount`: Amount of pool shares to withdraw.
 *   - `minAmountA`: Minimum amount of first asset to withdraw.
 *   - `minAmountB`: Minimum amount of second asset to withdraw.
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 */
export declare function liquidityPoolWithdraw(opts?: LiquidityPoolWithdrawOpts): xdr.Operation<LiquidityPoolWithdrawResult>;
