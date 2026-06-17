/**
 * Stellar helpers (UI runtime).
 *
 * JS only signs and submits WASM-prepared Soroban transactions.
 */

import { Address, Transaction, authorizeEntry, rpc, xdr } from '@stellar/stellar-sdk';
import { signWalletAuthEntry, signWalletTransaction } from './wallet.js';

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function needsWalletAuthEntry(entry, address) {
    const creds = entry.credentials();
    if (creds.switch() !== xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
        return false;
    }
    const addrAuth = creds.address();
    if (addrAuth.signature().switch().name !== 'scvVoid') {
        return false;
    }
    return Address.fromScAddress(addrAuth.address()).toString() === address;
}

async function signPreparedAuthEntry(entryXdr, { address, networkPassphrase, latestLedger, server }) {
    const entry = xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, 'base64');
    if (!needsWalletAuthEntry(entry, address)) {
        return entryXdr;
    }

    let validUntil = Number(entry.credentials().address().signatureExpirationLedger());
    if (!validUntil) {
        const ledgerSeq = latestLedger > 0
            ? latestLedger
            : (await server.getLatestLedger()).sequence;
        validUntil = ledgerSeq + 100;
    }

    const signed = await authorizeEntry(
        entry,
        async (preimage) => {
            const { signedAuthEntry } = await signWalletAuthEntry(
                preimage.toXDR('base64'),
                { address, networkPassphrase },
            );
            if (!signedAuthEntry) throw new Error('Auth entry signature was not returned');
            return Buffer.from(signedAuthEntry, 'base64');
        },
        validUntil,
        networkPassphrase,
    );

    return signed.toXDR('base64');
}

function patchAuthEntries(txXdr, signedAuthEntries) {
    const env = xdr.TransactionEnvelope.fromXDR(txXdr, 'base64');
    const v1 = env.v1();
    if (!v1) {
        throw new Error('Unsupported transaction envelope (expected v1)');
    }

    const auth = signedAuthEntries.map(e => xdr.SorobanAuthorizationEntry.fromXDR(e, 'base64'));
    for (const op of v1.tx().operations()) {
        const invoke = op.body()?.invokeHostFunctionOp?.();
        if (!invoke) continue;
        invoke.auth(auth);
        return env.toXDR('base64');
    }

    throw new Error('No invokeHostFunction operation found to attach auth entries');
}

/**
 * @param {{txXdr: string, authEntries: string[], latestLedger?: number}} prepared
 * @param {{address: string, rpcUrl: string, networkPassphrase: string}} ctx
 * @returns {Promise<string>} transaction hash
 */
export async function submitPreparedSorobanTx(prepared, ctx, opts = {}) {
    const { txXdr, authEntries, latestLedger = 0 } = prepared || {};
    const { address, rpcUrl, networkPassphrase } = ctx || {};
    const onStatus = typeof opts?.onStatus === 'function' ? opts.onStatus : null;

    const emit = (stage, message, current, total) => {
        if (!onStatus) return;
        try {
            const p = { stage, message };
            if (typeof current === 'number') p.current = current;
            if (typeof total === 'number') p.total = total;
            onStatus(p);
        } catch {
            // best-effort
        }
    };

    if (!txXdr || typeof txXdr !== 'string') throw new Error('Invalid prepared txXdr');
    if (!Array.isArray(authEntries)) throw new Error('Invalid prepared authEntries');
    if (!address) throw new Error('Missing address');
    if (!rpcUrl) throw new Error('Missing rpcUrl');
    if (!networkPassphrase) throw new Error('Missing networkPassphrase');

    const walletAuthTotal = authEntries.filter((entryXdr) =>
        needsWalletAuthEntry(xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, 'base64'), address),
    ).length;

    const server = new rpc.Server(rpcUrl);

    const signedAuthEntries = [];
    let walletAuthStep = 0;
    for (const entryXdr of authEntries) {
        if (needsWalletAuthEntry(xdr.SorobanAuthorizationEntry.fromXDR(entryXdr, 'base64'), address)) {
            walletAuthStep++;
            emit('sign_auth', `Approve authorization (${walletAuthStep}/${walletAuthTotal})…`, walletAuthStep, walletAuthTotal);
        }
        signedAuthEntries.push(
            await signPreparedAuthEntry(entryXdr, {
                address,
                networkPassphrase,
                latestLedger,
                server,
            }),
        );
    }

    const patchedTxXdr = walletAuthTotal > 0
        ? patchAuthEntries(txXdr, signedAuthEntries)
        : txXdr;

    emit('sign_tx', 'Approve transaction…');
    const { signedTxXdr } = await signWalletTransaction(patchedTxXdr, { address, networkPassphrase });
    if (!signedTxXdr) throw new Error('Transaction signature was not returned');
    emit('submit', 'Submitting…');
    const send = await server.sendTransaction(new Transaction(signedTxXdr, networkPassphrase));

    const hash = send?.hash;
    if (!hash) {
        const err = send?.errorResultXdr ? ` (errorResultXdr: ${send.errorResultXdr})` : '';
        throw new Error(`Transaction submission failed${err}`);
    }

    for (let i = 0; i < 30; i++) {
        emit('confirm', 'Confirming…', i + 1, 30);
        await sleep(1_000);
        const res = await server.getTransaction(hash);
        if (res?.status === 'SUCCESS') return hash;
        if (res?.status === 'FAILED') {
            const err = res?.resultXdr ? ` (resultXdr: ${res.resultXdr})` : '';
            throw new Error(`Transaction failed${err}`);
        }
    }

    throw new Error(`Transaction confirmation timed out after 30s (hash: ${hash})`);
}
