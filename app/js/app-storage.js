/**
 * App-layer persistence via SDK {@link Storage.call} (worker protocol).
 * Request/response field names use snake_case to match `StorageWorkerRequest`.
 */

const SETTING_EXPLORER = 'explorer';
const SETTING_BOOTNODE_CONFIG = 'bootnode_config';

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

    async getSetting(key) {
        const response = await this.#call({ GetSetting: key });
        const raw = response.Setting;
        if (raw == null) return null;
        return JSON.parse(raw);
    }

    async setSetting(key, value) {
        await this.#call({
            SetSetting: {
                key,
                value_json: JSON.stringify(value),
            },
        });
    }

    async getExplorerSetting() {
        return this.getSetting(SETTING_EXPLORER);
    }

    async getBootnodeConfig() {
        return this.getSetting(SETTING_BOOTNODE_CONFIG);
    }

    async setBootnodeConfig(url) {
        await this.setSetting(SETTING_BOOTNODE_CONFIG, { enabled: true, url });
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

    async getStoredBootnodeUrl() {
        const config = await this.getBootnodeConfig();
        if (config?.enabled && config.url) {
            return config.url;
        }
        return undefined;
    }
}
