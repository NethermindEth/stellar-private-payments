import { StrKey } from './strkey.js';
import { scValToNative } from './scval.js';

function extractEvent(event) {
  const contractId = typeof event.contractId === "function" ? event.contractId() : null;
  return {
    ...contractId !== null && contractId !== void 0 && {
      contractId: StrKey.encodeContract(contractId)
    },
    type: event.type().name,
    topics: event.body().value().topics().map((t) => scValToNative(t)),
    data: scValToNative(event.body().value().data())
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

export { humanizeEvents };
//# sourceMappingURL=events.js.map
