/**
 * App-layer persistence via SDK {@link Storage.call} (worker protocol).
 * Request/response field names use snake_case to match `StorageWorkerRequest`.
 */

const SETTING_EXPLORER = 'explorer';
const SETTING_BOOTNODE_CONFIG = 'bootnode_config';
const SETTING_TELEMETRY_CONFIG = 'telemetry_config';

// A setting is account-scoped if its value can reveal something about the
// account it is applied under; global if it is a presentation preference that
// is the same for everyone.
//
// bootnode_config: its operator sees which account is syncing, so sharing one
// endpoint across accounts links them.
// telemetry_config: revealSensitive un-redacts this account's amounts and
// addresses, and level decides how much of its activity is kept.
// explorer: public infrastructure, identical for every account.
const ACCOUNT_SCOPED_SETTINGS = new Set([SETTING_BOOTNODE_CONFIG, SETTING_TELEMETRY_CONFIG]);

/**
 * Storage key for a setting under a given account.
 *
 * Scoped settings are namespaced by address and require one — falling back to
 * the unscoped key is the inheritance this prevents. Legacy unscoped values are
 * not migrated: they belonged to whichever account was active when they were
 * written.
 */
function settingKey(key, address) {
    if (!ACCOUNT_SCOPED_SETTINGS.has(key)) return key;
    if (typeof address !== 'string' || address.length === 0) {
        throw new Error(`Setting "${key}" is account-scoped and requires an address`);
    }
    return `${key}::${address}`;
}

export { ACCOUNT_SCOPED_SETTINGS, SETTING_BOOTNODE_CONFIG, SETTING_TELEMETRY_CONFIG, SETTING_EXPLORER, settingKey };

/** Suggested archive URL when none is stored yet (wizard + sync-gap consent). */
export const DEFAULT_BOOTNODE_URL = 'https://bootnode.dev-nethermind.xyz';

function unwrapResponse(response) {
    if (response == null) {
        throw new Error('Empty storage response');
    }
    if (typeof response === 'object' && response.Error != null) {
        throw new Error(String(response.Error));
    }
    return response;
}

export async function storageCall(storage, request, timeoutMs = 5_000) {
    const response = unwrapResponse(await storage.call(request, timeoutMs));
    return response;
}

/**
 * App-only persistence: settings, disclaimer, operation history, onboarding key probe.
 */
export class AppStorage {
    #storage;

    constructor(storage) {
        this.#storage = storage;
    }

    async #call(request, timeoutMs = 5_000) {
        return storageCall(this.#storage, request, timeoutMs);
    }

    /**
     * @param {string} key
     * @param {string} [address] - required for account-scoped keys (see settingKey).
     */
    async getSetting(key, address) {
        const response = await this.#call({ GetSetting: settingKey(key, address) });
        const raw = response.Setting;
        if (raw == null) return null;
        return JSON.parse(raw);
    }

    /**
     * @param {string} key
     * @param {unknown} value
     * @param {string} [address] - required for account-scoped keys (see settingKey).
     */
    async setSetting(key, value, address) {
        await this.#call({
            SetSetting: {
                key: settingKey(key, address),
                value_json: JSON.stringify(value),
            },
        });
    }

    async getExplorerSetting() {
        return this.getSetting(SETTING_EXPLORER);
    }

    async getBootnodeConfig(address) {
        return this.getSetting(SETTING_BOOTNODE_CONFIG, address);
    }

    async setBootnodeConfig(url, address) {
        await this.setSetting(SETTING_BOOTNODE_CONFIG, { enabled: true, url }, address);
    }

    async getTelemetryConfig(address) {
        return this.getSetting(SETTING_TELEMETRY_CONFIG, address);
    }

    async setTelemetryConfig(config, address) {
        await this.setSetting(SETTING_TELEMETRY_CONFIG, config, address);
    }

    async getDisclaimerState(address) {
        const response = await this.#call({ DisclaimerState: address });
        return response.DisclaimerState ?? null;
    }

    /** Whether privacy keys are stored locally for an address (onboarding only). */
    async userKeysExist(address) {
        const response = await this.#call({ UserKeys: address }, 1_000);
        return response.UserKeys != null;
    }

    /** Public note/encryption keys only (onboarding; no ASP secret). */
    async getUserPublicKeys(address) {
        const response = await this.#call({ UserKeys: address }, 1_000);
        return response.UserKeys ?? null;
    }

    async acceptDisclaimer(address, disclaimerHashHex) {
        await this.#call({ AcceptDisclaimer: [address, disclaimerHashHex] });
    }

    async recordOperation(fields) {
        await this.#call({ RecordOperation: fields });
    }

    async listOperations(address, poolContractId, limit) {
        const response = await this.#call({
            ListOperations: {
                address,
                pool_contract_id: poolContractId,
                limit,
            },
        });
        return response.Operations ?? [];
    }

    /**
     * The configured archive URL for `address`, or undefined.
     *
     * Unlike getBootnodeConfig this tolerates a missing address, for the admin
     * page, which probes for an endpoint before any wallet is connected. With no
     * account to scope to it reads the pre-scoping global value; nothing writes
     * that key any more, so the fallback only ever sees data from before this
     * change and can go when the admin page opens an account first.
     */
    async getStoredBootnodeUrl(address) {
        const config = address
            ? await this.getBootnodeConfig(address)
            : await this.#getUnscopedBootnodeConfig();
        if (config?.enabled && config.url) {
            return config.url;
        }
        return undefined;
    }

    async #getUnscopedBootnodeConfig() {
        const response = await this.#call({ GetSetting: SETTING_BOOTNODE_CONFIG });
        const raw = response.Setting;
        if (raw == null) return null;
        return JSON.parse(raw);
    }
}
