import { OperationAttributes } from "../operations/types.js";
import xdr from "../xdr.js";
import type { BigNumber } from "./bignumber.js";
export declare const ONE = 10000000;
/** Sets the source account on the operation attributes from the opts.*/
export declare function setSourceAccount(opAttributes: OperationAttributes, opts: {
    source?: string;
}): void;
/**
 * Returns value converted to uint32 value or undefined.
 * If `value` is not `Number`, `String` or `Undefined` then throws an error.
 * Used in {@link Operation.setOptions}.
 *
 * @param name - name of the property (used in error message only)
 * @param value - value to check
 * @param isValidFunction - function to check other constraints (the argument will be a `Number`)
 */
export declare function checkUnsignedIntValue(name: string, value: number | string | undefined, isValidFunction?: ((value: number, name: string) => boolean) | null): number | undefined;
/**
 * Converts a string amount to an XDR Int64 value (scaled by 10^7).
 *
 * @param value - the amount as a string
 */
export declare function toXDRAmount(value: string): xdr.Int64;
/**
 * Converts an XDR Int64 amount to a decimal string (divided by 10^7).
 *
 * @param value - the XDR amount
 */
export declare function fromXDRAmount(value: xdr.Int64): string;
/**
 * Converts an XDR Price (n/d) to a decimal string.
 *
 * @param price - the XDR price object
 */
export declare function fromXDRPrice(price: xdr.Price): string;
/**
 * Converts a number, string, or `{n, d}` object to an XDR Price.
 *
 * @param price - the price as a number, string, or `{n, d}` fraction
 */
export declare function toXDRPrice(price: BigNumber | number | string | {
    n: number;
    d: number;
}): xdr.Price;
/**
 * Validates that a given amount is possible for a Stellar asset.
 *
 * Specifically, this means that the amount is well, a valid number, but also
 * that it is within the int64 range and has no more than 7 decimal levels of
 * precision.
 *
 * Note that while smart contracts allow larger amounts, this is oriented
 * towards validating the standard Stellar operations.
 *
 * @param value - the amount to validate
 * @param allowZero - optionally, whether or not zero is valid (default: no)
 */
export declare function isValidAmount(value: unknown, allowZero?: boolean): boolean;
/** Returns a standard error message for invalid amount arguments.*/
export declare function constructAmountRequirementsError(arg: string): string;
