import BigNumber from './util/bignumber.js';
import { StrKey } from './strkey.js';

class Account {
  _accountId;
  sequence;
  /**
   * @param accountId - ID of the account (ex.
   *     `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`). If you
   *     provide a muxed account address, this will throw; use {@link
   *     MuxedAccount} instead.
   * @param sequence - current sequence number of the account
   */
  constructor(accountId, sequence) {
    if (StrKey.isValidMed25519PublicKey(accountId)) {
      throw new Error("accountId is an M-address; use MuxedAccount instead");
    }
    if (!StrKey.isValidEd25519PublicKey(accountId)) {
      throw new Error("accountId is invalid");
    }
    if (!(typeof sequence === "string")) {
      throw new Error("sequence must be of type string");
    }
    let parsed;
    try {
      parsed = new BigNumber(sequence);
    } catch {
      throw new Error("sequence is not a valid number");
    }
    if (parsed.isNaN()) {
      throw new Error("sequence is not a valid number");
    }
    this._accountId = accountId;
    this.sequence = parsed;
  }
  /**
   * Returns Stellar account ID, ex.
   * `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`.
   */
  accountId() {
    return this._accountId;
  }
  /**
   * Returns sequence number for the account as a string
   */
  sequenceNumber() {
    return this.sequence.toString();
  }
  /**
   * Increments sequence number in this object by one.
   */
  incrementSequenceNumber() {
    this.sequence = this.sequence.plus(1);
  }
}

export { Account };
//# sourceMappingURL=account.js.map
