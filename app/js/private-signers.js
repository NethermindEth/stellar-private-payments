import { addSigner } from './signing-account.js';
const PREFIX = 'poolstellar_signers:';
const key = owner => `${PREFIX}${owner}`;
export const SIGNER_MIGRATION_WARNING_EVENT = 'spp:signer-migration-warning';
const MIGRATION_WARNING = 'Some saved signing accounts could not be loaded. You can still use your wallet and add signing accounts again. The unreadable legacy data has been preserved.';
function warnLegacySigners(message) {
    globalThis.window?.dispatchEvent(new CustomEvent(SIGNER_MIGRATION_WARNING_EVENT, { detail: message }));
}

/** Sweep every legacy owner after unlock, including owners no longer connected. */
export async function migratePrivateSigners(storage, legacy = localStorage, onWarning = warnLegacySigners) {
    // Snapshot names before deletion changes localStorage's numeric indices.
    const owners = [];
    for (let index = 0; index < legacy.length; index++) {
        const name = legacy.key(index);
        if (name?.startsWith(PREFIX) && name.length > PREFIX.length) {
            owners.push(name.slice(PREFIX.length));
        }
    }
    let warned = false;
    for (const owner of owners) await loadPrivateSigners(storage, owner, legacy, message => {
        if (!warned) { warned = true; onWarning(message); }
    });
}

/** Migrate legacy plaintext associations only after opening encrypted storage. */
export async function loadPrivateSigners(storage, owner, legacy = localStorage, onWarning = warnLegacySigners) {
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
    } catch {
        // A legacy preference must not prevent access to an unlocked database.
        // Preserve it for recovery without persisting an empty replacement.
        onWarning(MIGRATION_WARNING);
        return [];
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
