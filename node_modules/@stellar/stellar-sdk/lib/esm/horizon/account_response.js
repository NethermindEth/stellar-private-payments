import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js';
import '../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js';
import 'buffer';
import '../base/generated/curr_generated.js';
import '@noble/hashes/sha2.js';
import '../base/signing.js';
import '../base/keypair.js';
import 'base32.js';
import '../base/util/continued_fraction.js';
import '../base/util/bignumber.js';
import '../base/transaction_builder.js';
import { Account } from '../base/account.js';
import '../base/muxed_account.js';
import '../base/scval.js';
import '../base/numbers/uint128.js';
import '../base/numbers/uint256.js';
import '../base/numbers/int128.js';
import '../base/numbers/int256.js';

class AccountResponse {
  id;
  paging_token;
  account_id;
  sequence;
  sequence_ledger;
  sequence_time;
  subentry_count;
  home_domain;
  inflation_destination;
  last_modified_ledger;
  last_modified_time;
  thresholds;
  flags;
  balances;
  signers;
  num_sponsoring;
  num_sponsored;
  sponsor;
  data;
  data_attr;
  effects;
  offers;
  operations;
  payments;
  trades;
  transactions;
  _baseAccount;
  constructor(response) {
    this._baseAccount = new Account(response.account_id, response.sequence);
    this.effects = response.effects;
    this.offers = response.offers;
    this.operations = response.operations;
    this.payments = response.payments;
    this.trades = response.trades;
    this.data = response.data;
    this.transactions = response.transactions;
    this.id = response.id;
    this.paging_token = response.paging_token;
    this.account_id = response.account_id;
    this.sequence = response.sequence;
    this.sequence_ledger = response.sequence_ledger;
    this.sequence_time = response.sequence_time;
    this.subentry_count = response.subentry_count;
    this.home_domain = response.home_domain;
    this.inflation_destination = response.inflation_destination;
    this.last_modified_ledger = response.last_modified_ledger;
    this.last_modified_time = response.last_modified_time;
    this.thresholds = response.thresholds;
    this.flags = response.flags;
    this.balances = response.balances;
    this.signers = response.signers;
    this.data_attr = response.data_attr;
    this.sponsor = response.sponsor;
    this.num_sponsoring = response.num_sponsoring;
    this.num_sponsored = response.num_sponsored;
  }
  /**
   * Get Stellar account public key ex. `GB3KJPLFUYN5VL6R3GU3EGCGVCKFDSD7BEDX42HWG5BWFKB3KQGJJRMA`
   * @returns accountId
   */
  accountId() {
    return this._baseAccount.accountId();
  }
  /**
   * Get the current sequence number
   * @returns sequenceNumber
   */
  sequenceNumber() {
    return this._baseAccount.sequenceNumber();
  }
  /**
   * Increments sequence number in this object by one.
   * @returns    */
  incrementSequenceNumber() {
    this._baseAccount.incrementSequenceNumber();
    this.sequence = this._baseAccount.sequenceNumber();
  }
}

export { AccountResponse };
//# sourceMappingURL=account_response.js.map
