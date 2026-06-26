'use strict';

var buffer = require('buffer');
var utils = require('./utils.js');

function specFromWasm(wasm) {
  const customData = utils.parseWasmCustomSections(wasm);
  const xdrSections = customData.get("contractspecv0");
  if (!xdrSections || xdrSections.length === 0) {
    throw new Error("Could not obtain contract spec from wasm");
  }
  return buffer.Buffer.from(xdrSections[0]);
}

exports.specFromWasm = specFromWasm;
//# sourceMappingURL=wasm_spec_parser.js.map
