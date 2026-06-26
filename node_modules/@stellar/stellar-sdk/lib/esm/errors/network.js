class NetworkError extends Error {
  /** Response details, received from the Horizon server. */
  response;
  constructor(message, response) {
    super(message);
    this.response = response;
  }
  /**
   * Returns the error response sent by the Horizon server.
   * @returns Response details, received from the Horizon server.
   */
  getResponse() {
    return this.response;
  }
}

export { NetworkError };
//# sourceMappingURL=network.js.map
