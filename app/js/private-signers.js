import { addSigner } from './signing-account.js';
const PREFIX = 'poolstellar_signers:';
const key = owner => `${PREFIX}${owner}`;

/** Sweep every legacy owner after unlock, including owners no longer connected. */
export async function migratePrivateSigners(storage, legacy = localStorage) {
    // Snapshot names before deletion changes localStorage's numeric indices.
    const owners = [];
    for (let index = 0; index < legacy.length; index++) {
        const name = legacy.key(index);
        if (name?.startsWith(PREFIX) && name.length > PREFIX.length) {
            owners.push(name.slice(PREFIX.length));
        }
    }
    for (const owner of owners) await loadPrivateSigners(storage, owner, legacy);
}

/** Migrate legacy plaintext associations only after opening encrypted storage. */
export async function loadPrivateSigners(storage, owner, legacy = localStorage) {
    const saved = await storage.getSetting(key(owner));
    if (saved !== null) {
        legacy.removeItem(key(owner));
        return saved;
    }
    const raw = legacy.getItem(key(owner));
    let parsed;
    try {
        parsed = JSON.parse(raw ?? '[]');
        if (!Array.isArray(parsed)) throw new Error('Expected a signer list');
    } catch (cause) {
        throw new Error('Could not migrate legacy signing accounts: invalid saved list. The original data has been preserved.', { cause });
    }
    const signers = parsed.reduce((list, address) =>
        typeof address === 'string' ? addSigner(list, address, owner) : list, []);
    await storage.setSetting(key(owner), signers);
    legacy.removeItem(key(owner));
    return signers;
}
export async function savePrivateSigners(storage, owner, signers) {
    await storage.setSetting(key(owner), signers);
}
