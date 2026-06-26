import { CallBuilder } from './call_builder.js';

class LedgerCallBuilder extends CallBuilder {
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

export { LedgerCallBuilder };
//# sourceMappingURL=ledger_call_builder.js.map
