/** Verify a Stellar message signature and explain missing browser support. */
export async function verifyStorageSignature(publicKeyBytes, message, signature, crypto = globalThis.crypto) {
    try {
        const publicKey = await crypto.subtle.importKey('raw',
            publicKeyBytes, { name: 'Ed25519' }, false, ['verify']);
        const payload = new TextEncoder().encode(`Stellar Signed Message:\n${message}`);
        const digest = await crypto.subtle.digest('SHA-256', payload);
        return await crypto.subtle.verify('Ed25519', publicKey, signature, digest);
    } catch (error) {
        if (error?.name === 'NotSupportedError') {
            throw new Error('Your browser does not support the signature verification needed to unlock local storage. Update your browser to the latest version and try again.', { cause: error });
        }
        throw error;
    }
}
