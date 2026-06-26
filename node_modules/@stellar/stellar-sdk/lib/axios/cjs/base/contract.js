'use strict';

var address = require('./address.js');
var operation = require('./operation.js');
var curr_generated = require('./generated/curr_generated.js');
var strkey = require('./strkey.js');

class Contract {
  _id;
  /**
   * @param contractId - ID of the contract (ex.
   *     `CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE`).
   */
  constructor(contractId) {
    try {
      this._id = strkey.StrKey.decodeContract(contractId);
    } catch {
      throw new Error(`Invalid contract ID: ${contractId}`);
    }
  }
  /**
   * Returns Stellar contract ID as a strkey, ex.
   * `CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE`.
   */
  contractId() {
    return strkey.StrKey.encodeContract(this._id);
  }
  /** Returns the ID as a strkey (C...). */
  toString() {
    return this.contractId();
  }
  /** Returns the wrapped address of this contract. */
  address() {
    return address.Address.contract(this._id);
  }
  /**
   * Returns an operation that will invoke this contract call.
   *
   * @param method - name of the method to call
   * @param params - arguments to pass to the method, as an array of xdr.ScVal
   *
   * @see Operation.invokeHostFunction
   * @see Operation.invokeContractFunction
   * @see Operation.createCustomContract
   * @see Operation.createStellarAssetContract
   * @see Operation.uploadContractWasm
   */
  call(method, ...params) {
    return operation.Operation.invokeContractFunction({
      contract: this.address().toString(),
      function: method,
      args: params
    });
  }
  /**
   * Returns the read-only footprint entries necessary for any invocations to
   * this contract, for convenience when manually adding it to your
   * transaction's overall footprint or doing bump/restore operations.
   */
  getFootprint() {
    return curr_generated.default.LedgerKey.contractData(
      new curr_generated.default.LedgerKeyContractData({
        contract: this.address().toScAddress(),
        key: curr_generated.default.ScVal.scvLedgerKeyContractInstance(),
        durability: curr_generated.default.ContractDataDurability.persistent()
      })
    );
  }
}

exports.Contract = Contract;
//# sourceMappingURL=contract.js.map
