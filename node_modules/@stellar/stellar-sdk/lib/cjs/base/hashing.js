'use strict';

var buffer = require('buffer');
var sha2_js = require('@noble/hashes/sha2.js');

function hash(data) {
  const bytes = typeof data === "string" ? buffer.Buffer.from(data, "utf8") : data;
  return buffer.Buffer.from(sha2_js.sha256(bytes));
}

exports.hash = hash;
//# sourceMappingURL=hashing.js.map
