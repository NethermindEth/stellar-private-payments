'use strict';

const defaultConfig = {
  allowHttp: false,
  timeout: 0
};
let config = { ...defaultConfig };
class Config {
  /**
   * Sets `allowHttp` flag globally. When set to `true`, connections to insecure
   * http protocol servers will be allowed. Must be set to `false` in
   * production.
   * @defaultValue false
   */
  static setAllowHttp(value) {
    config.allowHttp = value;
  }
  /**
   * Sets `timeout` flag globally. When set to anything besides 0, the request
   * will timeout after specified time (ms).
   * @defaultValue 0
   */
  static setTimeout(value) {
    config.timeout = value;
  }
  /**
   * Returns the configured `allowHttp` flag.
   * @returns The allowHttp value.
   */
  static isAllowHttp() {
    return config.allowHttp;
  }
  /**
   * Returns the configured `timeout` flag.
   * @returns The timeout value.
   */
  static getTimeout() {
    return config.timeout;
  }
  /**
   * Sets all global config flags to default values.
   */
  static setDefault() {
    config = { ...defaultConfig };
  }
}

exports.Config = Config;
//# sourceMappingURL=config.js.map
