/**
 * App-layer persistence via SDK {@link Storage.call} (worker protocol).
 * Request/response field names use snake_case to match `StorageWorkerRequest`.
 */

const SETTING_EXPLORER = 'explorer';
const SETTING_BOOTNODE_CONFIG = 'bootnode_config';

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

    /**
     * @param {object} storage SDK storage handle.
     */
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

    /**
     * Binding status for an address: 'Absent', 'Acceptable', or a
     * `{ Mismatch: { stored } }` object.
     *
     * The deployment's requirement lives in the worker, which every route that
     * touches key material reads from, so this carries no binding of its own:
     * a second copy here could only go stale, and defaulting one would accept
     * a v1 row on a deployment that requires v2.
     *
     * Metadata only — this route never returns key material, which is what
     * lets the UI tell "not onboarded yet" from "keys exist but were derived
     * for a different deployment configuration". Asking the key-material
     * route that question is what previously made the two indistinguishable.
     */
    async keyBindingStatus(address) {
        const response = await this.#call({ KeyBindingStatus: address }, 1_000);
        return response.KeyBindingStatus ?? null;
    }

    /** Whether usable privacy keys are stored locally for an address (onboarding only). */
    async userKeysExist(address) {
        return (await this.keyBindingStatus(address)) === 'Acceptable';
    }

    /**
     * Public note/encryption keys only (onboarding; no ASP secret).
     *
     * Request this only once {@link keyBindingStatus} reports 'Acceptable':
     * on a mismatch it returns null, which must not be read as "no keys".
     */
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
