'use strict';

var axios = require('feaxios');
var types = require('./types.js');

function _interopDefault (e) { return e && e.__esModule ? e : { default: e }; }

var axios__default = /*#__PURE__*/_interopDefault(axios);

const CANCELED_MARKER = /* @__PURE__ */ Symbol.for("@stellar/stellar-sdk.canceled");
function makeCanceledError(reason) {
  const err = new Error(reason || "Request canceled");
  err[CANCELED_MARKER] = true;
  return err;
}
class InterceptorManager {
  handlers = [];
  use(fulfilled, rejected) {
    this.handlers.push({
      fulfilled,
      rejected
    });
    return this.handlers.length - 1;
  }
  eject(id) {
    if (this.handlers[id]) {
      this.handlers[id] = null;
    }
  }
  forEach(fn) {
    this.handlers.forEach((h) => {
      if (h !== null) {
        fn(h);
      }
    });
  }
}
function getFormConfig(config) {
  const formConfig = config || {};
  formConfig.headers = new Headers(formConfig.headers || {});
  formConfig.headers.set("Content-Type", "application/x-www-form-urlencoded");
  return formConfig;
}
function mergeWithDefaults(defaults, config) {
  if (!config) return { ...defaults };
  const merged = { ...defaults, ...config };
  if (defaults?.headers !== void 0 || config.headers !== void 0) {
    const headers = new Headers(defaults?.headers || {});
    new Headers(config.headers || {}).forEach((v, k) => {
      headers.set(k, v);
    });
    merged.headers = headers;
  }
  if (defaults?.params !== void 0 || config.params !== void 0) {
    merged.params = { ...defaults?.params || {}, ...config.params || {} };
  }
  return merged;
}
function buildBoundedUrl(config) {
  let url = config.url || "";
  if (config.baseURL && url && !/^https?:\/\//i.test(url)) {
    url = url.replace(/^\/?/, `${config.baseURL.replace(/\/$/, "")}/`);
  }
  if (config.params && Object.keys(config.params).length > 0) {
    const qs = new URLSearchParams(
      config.params
    ).toString();
    url += (url.includes("?") ? "&" : "?") + qs;
  }
  return url;
}
function encodeRequestBody(data, headers) {
  if (data === void 0 || data === null) return void 0;
  if (typeof data === "string") return data;
  if (data instanceof URLSearchParams) {
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/x-www-form-urlencoded");
    }
    return data;
  }
  if (data instanceof Blob || data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/octet-stream");
    }
    return data;
  }
  if (typeof FormData !== "undefined" && data instanceof FormData) {
    return data;
  }
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }
  return JSON.stringify(data);
}
async function readBodyBounded(response, maxContentLength) {
  if (maxContentLength !== void 0) {
    const headerLen = response.headers.get("content-length");
    if (headerLen && Number(headerLen) > maxContentLength) {
      throw new Error(`maxContentLength size of ${maxContentLength} exceeded`);
    }
  }
  if (!response.body) return new Uint8Array(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (maxContentLength !== void 0 && total > maxContentLength) {
        await reader.cancel();
        throw new Error(
          `maxContentLength size of ${maxContentLength} exceeded`
        );
      }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.byteLength;
  }
  return out;
}
function createTimeoutSignal(ms) {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(ms);
  }
  const controller = new AbortController();
  setTimeout(() => {
    const err = new Error("Timeout");
    err.name = "TimeoutError";
    controller.abort(err);
  }, ms);
  return controller.signal;
}
function composeSignals(signals) {
  if (signals.length === 0) return void 0;
  if (signals.length === 1) return signals[0];
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.any === "function") {
    return AbortSignal.any(signals);
  }
  const controller = new AbortController();
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    s.addEventListener("abort", () => controller.abort(s.reason), {
      once: true
    });
  }
  return controller.signal;
}
function canInspectManualRedirects() {
  return typeof process !== "undefined" && !!process.versions && !!process.versions.node;
}
function applyRedirectSemantics(init, status) {
  if (status === 307 || status === 308) return init;
  const next = { ...init, method: "GET", body: void 0 };
  const headers = new Headers(init.headers || {});
  headers.delete("content-type");
  headers.delete("content-length");
  headers.delete("transfer-encoding");
  next.headers = headers;
  return next;
}
function stripCrossOriginAuth(init, fromUrl, toUrl) {
  let sameOrigin;
  try {
    sameOrigin = new URL(fromUrl).origin === new URL(toUrl).origin;
  } catch {
    sameOrigin = false;
  }
  if (sameOrigin) return init;
  const headers = new Headers(init.headers || {});
  headers.delete("authorization");
  headers.delete("proxy-authorization");
  headers.delete("cookie");
  return { ...init, headers };
}
function buildHttpError(response, config, data) {
  const err = new Error(
    `Request failed with status code ${response.status}`
  );
  err.response = {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    data,
    config
  };
  return err;
}
async function boundedFetchAdapter(config) {
  const { maxRedirects, maxContentLength, timeout } = config;
  const signals = [];
  if (timeout && timeout > 0) {
    signals.push(createTimeoutSignal(timeout));
  }
  const signal = composeSignals(signals);
  const managedRedirects = maxRedirects !== void 0;
  const canManage = canInspectManualRedirects();
  let redirect;
  if (!managedRedirects) {
    redirect = "follow";
  } else if (canManage) {
    redirect = "manual";
  } else if (maxRedirects === 0) {
    redirect = "error";
  } else {
    redirect = "follow";
  }
  const headers = new Headers(config.headers || {});
  const body = encodeRequestBody(config.data, headers);
  let currentInit = {
    ...config.fetchOptions,
    method: (config.method || "get").toUpperCase(),
    headers,
    body,
    redirect,
    ...signal ? { signal } : {}
  };
  let currentUrl = buildBoundedUrl(config);
  let redirectsRemaining = maxRedirects ?? 0;
  let response;
  while (true) {
    try {
      response = await fetch(currentUrl, currentInit);
    } catch (err) {
      if (err?.name === "TimeoutError") {
        throw new Error(`timeout of ${config.timeout}ms exceeded`);
      }
      throw err;
    }
    const isManualRedirectResponse = redirect === "manual" && response.status >= 300 && response.status < 400;
    if (!isManualRedirectResponse) break;
    if (redirectsRemaining <= 0) {
      if (maxRedirects === 0) throw buildHttpError(response, config);
      throw new Error("Maximum number of redirects exceeded");
    }
    const location = response.headers.get("location");
    if (!location) break;
    const nextUrl = new URL(location, currentUrl).toString();
    currentInit = applyRedirectSemantics(currentInit, response.status);
    currentInit = stripCrossOriginAuth(currentInit, currentUrl, nextUrl);
    currentUrl = nextUrl;
    redirectsRemaining -= 1;
  }
  if (!response.ok) {
    let errBody;
    try {
      const errBytes = await readBodyBounded(response, maxContentLength);
      const errText = new TextDecoder().decode(errBytes);
      try {
        errBody = JSON.parse(errText);
      } catch {
        errBody = errText;
      }
    } catch (readErr) {
      throw readErr;
    }
    throw buildHttpError(response, config, errBody);
  }
  const bytes = await readBodyBounded(response, maxContentLength);
  const text = new TextDecoder().decode(bytes);
  let data = text;
  try {
    data = JSON.parse(text);
  } catch {
  }
  return {
    data,
    headers: response.headers,
    config,
    status: response.status,
    statusText: response.statusText
  };
}
function createFetchClient(fetchConfig = {}) {
  const defaults = {
    ...fetchConfig,
    headers: fetchConfig.headers || {}
  };
  const axiosStatic = axios__default.default.default ?? axios__default.default;
  const instance = axiosStatic.create(defaults);
  const requestInterceptors = new InterceptorManager();
  const responseInterceptors = new InterceptorManager();
  const httpClient = {
    interceptors: {
      request: requestInterceptors,
      response: responseInterceptors
    },
    defaults: {
      ...defaults,
      adapter: (config) => {
        if (config.maxRedirects !== void 0 || config.maxContentLength !== void 0) {
          return boundedFetchAdapter(config);
        }
        return instance.request(config);
      }
    },
    create(config) {
      return createFetchClient({ ...this.defaults, ...config });
    },
    makeRequest(config) {
      return new Promise((resolve, reject) => {
        function processRequest(finalConfig, res, rej) {
          const adapter = finalConfig.adapter || this.defaults.adapter;
          if (!adapter) {
            throw new Error("No adapter available");
          }
          let responsePromise = adapter(finalConfig).then((axiosResponse) => {
            const httpClientResponse = {
              data: axiosResponse.data,
              headers: axiosResponse.headers,
              config: axiosResponse.config,
              status: axiosResponse.status,
              statusText: axiosResponse.statusText
            };
            return httpClientResponse;
          });
          if (responseInterceptors.handlers.length > 0) {
            const chain = responseInterceptors.handlers.filter(
              (interceptor) => interceptor !== null
            ).flatMap((interceptor) => [
              interceptor.fulfilled,
              interceptor.rejected
            ]);
            for (let i = 0, len = chain.length; i < len; i += 2) {
              responsePromise = responsePromise.then(
                (response) => {
                  const fulfilledInterceptor = chain[i];
                  if (typeof fulfilledInterceptor === "function") {
                    return fulfilledInterceptor(response);
                  }
                  return response;
                },
                (error) => {
                  const rejectedInterceptor = chain[i + 1];
                  if (typeof rejectedInterceptor === "function") {
                    return rejectedInterceptor(error);
                  }
                  throw error;
                }
              ).then((interceptedResponse) => interceptedResponse);
            }
          }
          responsePromise.then(res).catch(rej);
        }
        const abortController = new AbortController();
        config.signal = abortController.signal;
        if (config.cancelToken) {
          const { cancelToken } = config;
          cancelToken.promise.then(() => {
            abortController.abort();
            reject(makeCanceledError(cancelToken.reason));
          });
        }
        const modifiedConfig = config;
        if (requestInterceptors.handlers.length > 0) {
          const chain = requestInterceptors.handlers.filter(
            (interceptor) => interceptor !== null
          ).flatMap((interceptor) => [
            interceptor.fulfilled,
            interceptor.rejected
          ]);
          let configPromise = Promise.resolve(modifiedConfig);
          for (let i = 0, len = chain.length; i < len; i += 2) {
            configPromise = configPromise.then(
              chain[i],
              chain[i + 1]
            );
          }
          configPromise.then((resolvedConfig) => {
            processRequest.call(this, resolvedConfig, resolve, reject);
          }).catch(reject);
          return;
        }
        processRequest.call(this, modifiedConfig, resolve, reject);
      });
    },
    get(url, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "get"
      });
    },
    delete(url, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "delete"
      });
    },
    head(url, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "head"
      });
    },
    options(url, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "options"
      });
    },
    post(url, data, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "post",
        data
      });
    },
    put(url, data, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "put",
        data
      });
    },
    patch(url, data, config) {
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, config),
        url,
        method: "patch",
        data
      });
    },
    postForm(url, data, config) {
      const formConfig = getFormConfig(config);
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, formConfig),
        url,
        method: "post",
        data
      });
    },
    putForm(url, data, config) {
      const formConfig = getFormConfig(config);
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, formConfig),
        url,
        method: "put",
        data
      });
    },
    patchForm(url, data, config) {
      const formConfig = getFormConfig(config);
      return this.makeRequest({
        ...mergeWithDefaults(this.defaults, formConfig),
        url,
        method: "patch",
        data
      });
    },
    CancelToken: types.CancelToken,
    isCancel: (value) => value instanceof Error && value[CANCELED_MARKER] === true
  };
  return httpClient;
}
const fetchClient = createFetchClient();

exports.create = createFetchClient;
exports.fetchClient = fetchClient;
//# sourceMappingURL=fetch-client.js.map
