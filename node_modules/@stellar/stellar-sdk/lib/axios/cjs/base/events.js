'use strict';

var strkey = require('./strkey.js');
var scval = require('./scval.js');

function extractEvent(event) {
  const contractId = typeof event.contractId === "function" ? event.contractId() : null;
  return {
    ...contractId !== null && contractId !== void 0 && {
      contractId: strkey.StrKey.encodeContract(contractId)
    },
    type: event.type().name,
    topics: event.body().value().topics().map((t) => scval.scValToNative(t)),
    data: scval.scValToNative(event.body().value().data())
  };
}
function humanizeEvents(events) {
  return events.map((e) => {
    if ("inSuccessfulContractCall" in e) {
      return extractEvent(e.event());
    }
    return extractEvent(e);
  });
}

exports.humanizeEvents = humanizeEvents;
//# sourceMappingURL=events.js.map
