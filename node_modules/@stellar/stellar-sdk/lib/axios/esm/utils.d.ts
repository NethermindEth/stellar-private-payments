import { Transaction } from "./base/index.js";
/**
 * Miscellaneous utilities.
 *
 */
export declare class Utils {
    /**
     * Verifies if the current date is within the transaction's timebounds
     *
     * @param transaction - The transaction whose timebounds will be validated.
     * @param gracePeriod - (optional) An additional window of time that should be considered valid on either end of the transaction's time range.
     *
     * @returns Returns true if the current time is within the transaction's [minTime, maxTime] range.
     *
     */
    static validateTimebounds(transaction: Transaction, gracePeriod?: number): boolean;
    static sleep(ms: number): Promise<void>;
}
