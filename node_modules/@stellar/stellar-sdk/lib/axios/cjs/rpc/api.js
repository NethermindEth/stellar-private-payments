'use strict';

exports.Api = void 0;
((Api2) => {
  ((GetTransactionStatus2) => {
    GetTransactionStatus2["SUCCESS"] = "SUCCESS";
    GetTransactionStatus2["NOT_FOUND"] = "NOT_FOUND";
    GetTransactionStatus2["FAILED"] = "FAILED";
  })(Api2.GetTransactionStatus || (Api2.GetTransactionStatus = {}));
  function isSimulationError(sim) {
    return "error" in sim;
  }
  Api2.isSimulationError = isSimulationError;
  function isSimulationSuccess(sim) {
    return "transactionData" in sim;
  }
  Api2.isSimulationSuccess = isSimulationSuccess;
  function isSimulationRestore(sim) {
    return isSimulationSuccess(sim) && "restorePreamble" in sim && !!sim.restorePreamble.transactionData;
  }
  Api2.isSimulationRestore = isSimulationRestore;
  function isSimulationRaw(sim) {
    return !sim._parsed;
  }
  Api2.isSimulationRaw = isSimulationRaw;
})(exports.Api || (exports.Api = {}));
//# sourceMappingURL=api.js.map
