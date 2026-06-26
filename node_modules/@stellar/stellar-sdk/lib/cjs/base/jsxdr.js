'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-int.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/unsigned-hyper.js');
require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/xdr-type.js');
require('buffer');
var xdrReader = require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/serialization/xdr-reader.js');
var xdrWriter = require('../node_modules/.pnpm/@stellar_js-xdr@4.0.0/node_modules/@stellar/js-xdr/src/serialization/xdr-writer.js');

const cereal = { XdrWriter: xdrWriter.XdrWriter, XdrReader: xdrReader.XdrReader };

exports.XdrReader = xdrReader.XdrReader;
exports.XdrWriter = xdrWriter.XdrWriter;
exports.default = cereal;
//# sourceMappingURL=jsxdr.js.map
