'use strict';

class Utils {
  /**
   * Verifies if the current date is within the transaction's timebounds
   *
   * @param transaction - The transaction whose timebounds will be validated.
   * @param gracePeriod - (optional) An additional window of time that should be considered valid on either end of the transaction's time range.
   *
   * @returns Returns true if the current time is within the transaction's [minTime, maxTime] range.
   *
   */
  static validateTimebounds(transaction, gracePeriod = 0) {
    if (!transaction.timeBounds) {
      return false;
    }
    const now = Math.floor(Date.now() / 1e3);
    const { minTime, maxTime } = transaction.timeBounds;
    return now >= Number.parseInt(minTime, 10) - gracePeriod && now <= Number.parseInt(maxTime, 10) + gracePeriod;
  }
  static sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

exports.Utils = Utils;
//# sourceMappingURL=utils.js.map
