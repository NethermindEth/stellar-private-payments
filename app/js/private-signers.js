import { rememberedSigners } from './signing-account.js';
const key = owner => `poolstellar_signers:${owner}`;

/** Migrate legacy plaintext associations only after opening encrypted storage. */
export async function loadPrivateSigners(storage, owner, legacy = localStorage) {
    const saved = await storage.getSetting(key(owner));
    if (saved !== null) {
        legacy.removeItem(key(owner));
        return saved;
    }
    const signers = rememberedSigners(owner, legacy);
    await storage.setSetting(key(owner), signers);
    legacy.removeItem(key(owner));
    return signers;
}
export async function savePrivateSigners(storage, owner, signers) {
    await storage.setSetting(key(owner), signers);
}
