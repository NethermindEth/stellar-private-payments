/**
 * App-layer persistence via SDK {@link Storage.call} (worker protocol).
 * Request/response field names use snake_case to match `StorageWorkerRequest`.
 */

const KEY_DERIVATION_MESSAGE = 'Privacy Pool Key Derivation [v1]';

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

export async function getSetting(storage, key) {
    const response = await storageCall(storage, { GetSetting: key });
    const raw = response.Setting;
    if (raw == null) return null;
    return JSON.parse(raw);
}

export async function setSetting(storage, key, value) {
    await storageCall(storage, {
        SetSetting: {
            key,
            value_json: JSON.stringify(value),
        },
    });
}

export async function getExplorerSetting(storage) {
    return getSetting(storage, SETTING_EXPLORER);
}

export async function getBootnodeConfig(storage) {
    return getSetting(storage, SETTING_BOOTNODE_CONFIG);
}

export async function setBootnodeConfig(storage, url) {
    await setSetting(storage, SETTING_BOOTNODE_CONFIG, { enabled: true, url });
}

export async function getDisclaimerState(storage, address) {
    const response = await storageCall(storage, { DisclaimerState: address });
    return response.DisclaimerState ?? null;
}

export async function acceptDisclaimer(storage, address, disclaimerHashHex) {
    await storageCall(storage, { AcceptDisclaimer: [address, disclaimerHashHex] });
}

export async function getUserKeys(storage, address) {
    const response = await storageCall(storage, { UserKeys: address });
    return response.UserKeys ?? null;
}

export async function getAspSecret(storage, address) {
    const response = await storageCall(storage, { AspSecret: address });
    return response.AspSecret ?? null;
}

export async function deriveAndSaveUserKeys(storage, address, signatureBytes, network) {
    await storageCall(
        storage,
        {
            DeriveSaveUserKeys: [address, Array.from(signatureBytes), network],
        },
        10_000,
    );
}

export function keyDerivationMessage() {
    return KEY_DERIVATION_MESSAGE;
}

export async function getPortfolioBalances(storage, address) {
    const response = await storageCall(storage, { PortfolioBalances: address });
    return response.PortfolioBalances ?? [];
}

export async function getOperationalFeed(storage, limit, contractConfig) {
    const response = await storageCall(storage, {
        OperationalFeed: {
            limit,
            asp_membership_contract_id: contractConfig.asp_membership,
            public_key_registry_contract_id: contractConfig.public_key_registry,
        },
    });
    return response.OperationalFeed ?? [];
}

export async function getUserNotes(storage, address, limit) {
    const response = await storageCall(storage, { UserNotes: [address, limit] });
    return response.UserNotes ?? [];
}

export async function getRecentPublicKeys(storage, limit) {
    const response = await storageCall(storage, { RecentPubKeys: limit });
    return response.PubKeys ?? [];
}

export async function recordOperation(storage, fields) {
    await storageCall(storage, { RecordOperation: fields });
}

export async function listOperations(storage, address, poolContractId, limit) {
    const response = await storageCall(storage, {
        ListOperations: {
            address,
            pool_contract_id: poolContractId,
            limit,
        },
    });
    return response.Operations ?? [];
}

export async function deriveAspUserLeaf(storage, membershipBlinding, pubkeyHex) {
    const response = await storageCall(storage, {
        DeriveASPleaf: {
            membershipBlinding: membershipBlinding.toString(),
            pubkey: pubkeyHex,
        },
    });
    const leaf = response.DeriveASPleaf;
    if (leaf == null) {
        throw new Error('DeriveASPleaf returned no leaf');
    }
    return typeof leaf === 'string' ? leaf : String(leaf);
}
