const key = owner => `poolstellar_signers:${owner}`;

/** The saved signing accounts of `owner`, from encrypted storage. */
export async function loadPrivateSigners(storage, owner) {
    return (await storage.getSetting(key(owner))) ?? [];
}
export async function savePrivateSigners(storage, owner, signers) {
    await storage.setSetting(key(owner), signers);
}
