import { create } from '../http-client/axios-client.js';

const version = "16.0.1";
const SERVER_TIME_MAP = {};
function toSeconds(ms) {
  return Math.floor(ms / 1e3);
}
function createHttpClient(headers) {
  const httpClient = create({
    headers: {
      ...headers,
      "X-Client-Name": "js-stellar-sdk",
      "X-Client-Version": version
    }
  });
  httpClient.interceptors.response.use((response) => {
    const responeUrl = response.config.url;
    if (!responeUrl) {
      return response;
    }
    const url = new URL(responeUrl);
    const port = url.port;
    const hostname = port ? `${url.hostname}:${port}` : url.hostname;
    let serverTime = 0;
    if (response.headers instanceof Headers) {
      const dateHeader = response.headers.get("date");
      if (dateHeader) {
        serverTime = toSeconds(Date.parse(dateHeader));
      }
    } else if (typeof response.headers === "object" && "date" in response.headers) {
      const responseHeader = response.headers;
      if (typeof responseHeader.date === "string") {
        serverTime = toSeconds(Date.parse(responseHeader.date));
      }
    }
    const localTimeRecorded = toSeconds((/* @__PURE__ */ new Date()).getTime());
    if (!Number.isNaN(serverTime)) {
      SERVER_TIME_MAP[hostname] = {
        serverTime,
        localTimeRecorded
      };
    }
    return response;
  });
  return httpClient;
}
function getCurrentServerTime(hostname) {
  const entry = SERVER_TIME_MAP[hostname];
  if (!entry || !entry.localTimeRecorded || !entry.serverTime) {
    return null;
  }
  const { serverTime, localTimeRecorded } = entry;
  const currentTime = toSeconds((/* @__PURE__ */ new Date()).getTime());
  if (currentTime - localTimeRecorded > 60 * 5) {
    return null;
  }
  return currentTime - localTimeRecorded + serverTime;
}

export { SERVER_TIME_MAP, createHttpClient, getCurrentServerTime, version };
//# sourceMappingURL=horizon_axios_client.js.map
