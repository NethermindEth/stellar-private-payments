import { EventSource } from 'eventsource';
import { NetworkError } from '../errors/network.js';
import { NotFoundError } from '../errors/not_found.js';
import { BadRequestError } from '../errors/bad_request.js';
import { version } from './horizon_axios_client.js';
import { expandUriTemplate } from '../utils/url.js';

const JOINABLE = ["transaction"];
class CallBuilder {
  url;
  filter;
  originalSegments;
  neighborRoot;
  httpClient;
  constructor(serverUrl, httpClient, neighborRoot = "") {
    this.url = new URL(serverUrl);
    this.filter = [];
    this.originalSegments = this.url.pathname.split("/").filter((s) => s.length > 0);
    this.neighborRoot = neighborRoot;
    this.httpClient = httpClient;
  }
  setPath(...segments) {
    const endpointSegments = segments.flatMap(
      (segment) => segment.split("/").filter((s) => s.length > 0)
    );
    this.url.pathname = this.originalSegments.concat(endpointSegments).join("/");
  }
  /**
   * Triggers a HTTP request using this builder's current configuration.
   * @returns a Promise that resolves to the server's response.
   */
  call() {
    this.checkFilter();
    return this._sendNormalRequest(this.url).then(
      (r) => this._parseResponse(r)
    );
  }
  //// TODO: Migrate to async, BUT that's a change in behavior and tests "rejects two filters" will fail.
  //// It's because async will check within promise, which makes more sense when using awaits instead of Promises.
  // public async call(): Promise<T> {
  //   this.checkFilter();
  //   const r = await this._sendNormalRequest(this.url);
  //   return this._parseResponse(r);
  // }
  //// /* actually equals */
  //// public call(): Promise<T> {
  ////   return Promise.resolve().then(() => {
  ////     this.checkFilter();
  ////     return this._sendNormalRequest(this.url)
  ////   }).then((r) => {
  ////     this._parseResponse(r)
  ////   });
  //// }
  /**
   * Creates an EventSource that listens for incoming messages from the server. To stop listening for new
   * events call the function returned by this method.
   * @see [Horizon Response Format](https://developers.stellar.org/api/introduction/response-format/)
   * @see [MDN EventSource](https://developer.mozilla.org/en-US/docs/Web/API/EventSource)
   * @param options - (optional) EventSource options.
   *   - `onmessage` (optional): Callback function to handle incoming messages.
   *   - `onerror` (optional): Callback function to handle errors.
   *   - `reconnectTimeout` (optional): Custom stream connection timeout in ms, default is 15 seconds.
   * @returns Close function. Run to close the connection and stop listening for new events.
   */
  stream(options = {}) {
    this.checkFilter();
    const streamUrl = new URL(this.url);
    streamUrl.searchParams.set("X-Client-Name", "js-stellar-sdk");
    streamUrl.searchParams.set("X-Client-Version", version);
    const { headers } = this.httpClient.defaults;
    if (headers) {
      const headerNames = ["X-App-Name", "X-App-Version"];
      headerNames.forEach((name) => {
        let value;
        if (headers instanceof Headers) {
          value = headers.get(name) ?? void 0;
        } else if (Array.isArray(headers)) {
          const entry = headers.find(([key]) => key === name);
          value = entry?.[1];
        } else {
          value = headers[name];
        }
        if (value) {
          streamUrl.searchParams.set(name, value);
        }
      });
    }
    let es;
    let timeout;
    const createTimeout = () => {
      timeout = setTimeout(
        () => {
          es?.close();
          es = createEventSource();
        },
        options.reconnectTimeout || 15 * 1e3
      );
    };
    const createEventSource = () => {
      try {
        es = new EventSource(streamUrl.toString());
      } catch (err) {
        if (options.onerror) {
          options.onerror(err);
        }
      }
      createTimeout();
      if (!es) {
        return es;
      }
      let closed = false;
      const onClose = () => {
        if (closed) {
          return;
        }
        clearTimeout(timeout);
        es.close();
        createEventSource();
        closed = true;
      };
      const onMessage = (message) => {
        if (message.type === "close") {
          onClose();
          return;
        }
        const result = message.data ? this._parseRecord(JSON.parse(message.data)) : message;
        if (result.paging_token) {
          streamUrl.searchParams.set("cursor", result.paging_token);
        }
        clearTimeout(timeout);
        createTimeout();
        if (typeof options.onmessage !== "undefined") {
          options.onmessage(result);
        }
      };
      const onError = (error) => {
        if (options.onerror) {
          options.onerror(error);
        }
      };
      if (es.addEventListener) {
        es.addEventListener("message", onMessage.bind(this));
        es.addEventListener("error", onError.bind(this));
        es.addEventListener("close", onClose.bind(this));
      } else {
        es.onmessage = onMessage.bind(this);
        es.onerror = onError.bind(this);
      }
      return es;
    };
    createEventSource();
    return () => {
      clearTimeout(timeout);
      es?.close();
    };
  }
  /**
   * Sets `cursor` parameter for the current call. Returns the CallBuilder object on which this method has been called.
   * @see [Paging](https://developers.stellar.org/api/introduction/pagination/)
   * @param cursor - A cursor is a value that points to a specific location in a collection of resources.
   * @returns current CallBuilder instance
   */
  cursor(cursor) {
    this.url.searchParams.set("cursor", cursor);
    return this;
  }
  /**
   * Sets `limit` parameter for the current call. Returns the CallBuilder object on which this method has been called.
   * @see [Paging](https://developers.stellar.org/api/introduction/pagination/)
   * @param recordsNumber - Number of records the server should return.
   * @returns current CallBuilder instance
   */
  limit(recordsNumber) {
    this.url.searchParams.set("limit", recordsNumber.toString());
    return this;
  }
  /**
   * Sets `order` parameter for the current call. Returns the CallBuilder object on which this method has been called.
   * @param direction - Sort direction
   * @returns current CallBuilder instance
   */
  order(direction) {
    this.url.searchParams.set("order", direction);
    return this;
  }
  /**
   * Sets `join` parameter for the current call. The `join` parameter
   * includes the requested resource in the response. Currently, the
   * only valid value for the parameter is `transactions` and is only
   * supported on the operations and payments endpoints. The response
   * will include a `transaction` field for each operation in the
   * response.
   *
   * @param include - join Records to be included in the response.
   * @returns current CallBuilder instance.
   */
  join(include) {
    this.url.searchParams.set("join", include);
    return this;
  }
  /**
   * A helper method to craft queries to "neighbor" endpoints.
   *
   *  For example, we have an `/effects` suffix endpoint on many different
   *  "root" endpoints, such as `/transactions/:id` and `/accounts/:id`. So,
   *  it's helpful to be able to conveniently create queries to the
   *  `/accounts/:id/effects` endpoint:
   *
   *    `this.forEndpoint("accounts", accountId)`.
   *
   * @param endpoint - neighbor endpoint in question, like /operations
   * @param param - filter parameter, like an operation ID
   *
   * @returns this CallBuilder instance
   */
  forEndpoint(endpoint, param) {
    if (this.neighborRoot === "") {
      throw new Error("Invalid usage: neighborRoot not set in constructor");
    }
    this.filter.push([endpoint, param, this.neighborRoot]);
    return this;
  }
  /**
   * @hidden
   * @returns    */
  checkFilter() {
    if (this.filter.length >= 2) {
      throw new BadRequestError("Too many filters specified", this.filter);
    }
    if (this.filter.length === 1) {
      const newSegment = this.originalSegments.concat(this.filter[0]);
      this.url.pathname = newSegment.join("/");
    }
  }
  /**
   * Convert a link object to a function that fetches that link.
   * @hidden
   * @param link - A link object
   *   - `href`: the URI of the link
   *   - `templated` (optional): Whether the link is templated
   * @returns A function that requests the link
   */
  _requestFnForLink(link) {
    return async (opts = {}) => {
      let uri;
      if (link.templated) {
        uri = new URL(expandUriTemplate(link.href, opts), this.url);
      } else {
        uri = new URL(link.href, this.url);
      }
      const r = await this._sendNormalRequest(uri);
      return this._parseResponse(r);
    };
  }
  /**
   * Given the json response, find and convert each link into a function that
   * calls that link.
   * @hidden
   * @param json - JSON response
   * @returns JSON response with string links replaced with functions
   */
  _parseRecord(json) {
    if (!json._links) {
      return json;
    }
    Object.keys(json._links).forEach((key) => {
      const n = json._links[key];
      let included = false;
      if (typeof json[key] !== "undefined") {
        json[`${key}_attr`] = json[key];
        included = true;
      }
      if (included && JOINABLE.indexOf(key) >= 0) {
        const record = this._parseRecord(json[key]);
        json[key] = async () => record;
      } else {
        json[key] = this._requestFnForLink(n);
      }
    });
    return json;
  }
  async _sendNormalRequest(initialUrl) {
    const url = new URL(initialUrl);
    url.protocol = this.url.protocol;
    url.host = this.url.host;
    return this.httpClient.get(url.toString()).then((response) => response.data).catch(this._handleNetworkError);
  }
  /**
   * @hidden
   * @param json - Response object
   * @returns Extended response
   */
  _parseResponse(json) {
    if (json._embedded && json._embedded.records) {
      return this._toCollectionPage(json);
    }
    return this._parseRecord(json);
  }
  /**
   * @hidden
   * @param json - Response object
   * @returns Extended response object
   */
  _toCollectionPage(json) {
    for (let i = 0; i < json._embedded.records.length; i += 1) {
      json._embedded.records[i] = this._parseRecord(json._embedded.records[i]);
    }
    return {
      records: json._embedded.records,
      next: async () => {
        const r = await this._sendNormalRequest(
          new URL(json._links.next.href, this.url)
        );
        return this._toCollectionPage(r);
      },
      prev: async () => {
        const r = await this._sendNormalRequest(
          new URL(json._links.prev.href, this.url)
        );
        return this._toCollectionPage(r);
      }
    };
  }
  /**
   * @hidden
   * @param error - Network error object
   * @returns Promise that rejects with a human-readable error
   */
  async _handleNetworkError(error) {
    if (error.response && error.response.status) {
      switch (error.response.status) {
        case 404:
          return Promise.reject(
            new NotFoundError(
              error.response.statusText ?? "Not Found",
              error.response.data
            )
          );
        default:
          return Promise.reject(
            new NetworkError(
              error.response.statusText ?? "Unknown",
              error.response.data
            )
          );
      }
    } else {
      return Promise.reject(new Error(error.message));
    }
  }
}

export { CallBuilder };
//# sourceMappingURL=call_builder.js.map
