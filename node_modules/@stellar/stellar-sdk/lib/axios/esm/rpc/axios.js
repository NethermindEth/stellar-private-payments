import { create } from '../http-client/axios-client.js';

const version = "16.0.1";
function createHttpClient(headers) {
  return create({
    headers: {
      ...headers,
      "X-Client-Name": "js-stellar-sdk",
      "X-Client-Version": version
    }
  });
}

export { createHttpClient, version };
//# sourceMappingURL=axios.js.map
