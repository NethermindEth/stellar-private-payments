import { Buffer } from 'buffer';
import { parseWasmCustomSections } from './utils.js';

function specFromWasm(wasm) {
  const customData = parseWasmCustomSections(wasm);
  const xdrSections = customData.get("contractspecv0");
  if (!xdrSections || xdrSections.length === 0) {
    throw new Error("Could not obtain contract spec from wasm");
  }
  return Buffer.from(xdrSections[0]);
}

export { specFromWasm };
//# sourceMappingURL=wasm_spec_parser.js.map
