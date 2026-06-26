/**
 * Global config parameters.
 */
export interface Configuration {
    /**
     * Allow connecting to http servers. This must be set to false in production deployments!
     * @defaultValue false
     */
    allowHttp: boolean;
    /**
     * Allow a timeout. Allows user to avoid nasty lag due network issues.
     * @defaultValue 0
     */
    timeout: number;
}
/**
 * Global config class.
 * @example Usage in node
 * ```ts
 * import { Config } from '@stellar/stellar-sdk';
 * Config.setAllowHttp(true);
 * Config.setTimeout(5000);
 * ```
 *
 * @example Usage in the browser
 * ```ts
 * StellarSdk.Config.setAllowHttp(true);
 * StellarSdk.Config.setTimeout(5000);
 * ```
 */
declare class Config {
    /**
     * Sets `allowHttp` flag globally. When set to `true`, connections to insecure
     * http protocol servers will be allowed. Must be set to `false` in
     * production.
     * @defaultValue false
     */
    static setAllowHttp(value: boolean): void;
    /**
     * Sets `timeout` flag globally. When set to anything besides 0, the request
     * will timeout after specified time (ms).
     * @defaultValue 0
     */
    static setTimeout(value: number): void;
    /**
     * Returns the configured `allowHttp` flag.
     * @returns The allowHttp value.
     */
    static isAllowHttp(): boolean;
    /**
     * Returns the configured `timeout` flag.
     * @returns The timeout value.
     */
    static getTimeout(): number;
    /**
     * Sets all global config flags to default values.
     */
    static setDefault(): void;
}
export { Config };
