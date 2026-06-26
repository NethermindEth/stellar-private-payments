'use strict';

var call_builder = require('./call_builder.js');

class LedgerCallBuilder extends call_builder.CallBuilder {
  constructor(serverUrl, httpClient) {
    super(serverUrl, httpClient);
    this.setPath("ledgers");
  }
  /**
   * Provides information on a single ledger.
   * @param sequence - Ledger sequence
   * @returns current LedgerCallBuilder instance
   */
  ledger(sequence) {
    this.filter.push(["ledgers", sequence.toString()]);
    return this;
  }
}

exports.LedgerCallBuilder = LedgerCallBuilder;
//# sourceMappingURL=ledger_call_builder.js.map
