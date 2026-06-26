import xdr from "../xdr.js";
import { LiquidityPoolDepositResult, LiquidityPoolDepositOpts } from "./types.js";
/**
 * Creates a liquidity pool deposit operation.
 *
 * @see https://developers.stellar.org/docs/start/list-of-operations/#liquidity-pool-deposit
 *
 * @param opts - Options object
 *   - `liquidityPoolId`: The liquidity pool ID.
 *   - `maxAmountA`: Maximum amount of first asset to deposit.
 *   - `maxAmountB`: Maximum amount of second asset to deposit.
 *   - `minPrice`: Minimum depositA/depositB price.
 *   - `minPrice.n`: If `opts.minPrice` is an object: the price numerator
 *   - `minPrice.d`: If `opts.minPrice` is an object: the price denominator
 *   - `maxPrice`: Maximum depositA/depositB price.
 *   - `maxPrice.n`: If `opts.maxPrice` is an object: the price numerator
 *   - `maxPrice.d`: If `opts.maxPrice` is an object: the price denominator
 *   - `source`: The source account for the operation. Defaults to the transaction's source account.
 */
export declare function liquidityPoolDeposit(opts?: LiquidityPoolDepositOpts): xdr.Operation<LiquidityPoolDepositResult>;
