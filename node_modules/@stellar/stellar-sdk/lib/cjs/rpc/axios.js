'use strict';

var fetchClient = require('../http-client/fetch-client.js');

const version = "16.0.1";
function createHttpClient(headers) {
  return fetchClient.create({
    headers: {
      ...headers,
      "X-Client-Name": "js-stellar-sdk",
      "X-Client-Version": version
    }
  });
}

exports.createHttpClient = createHttpClient;
exports.version = version;
//# sourceMappingURL=axios.js.map
