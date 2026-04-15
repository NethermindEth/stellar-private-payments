/**
 * Stellar helpers (UI runtime).
 *
 * Kept intentionally small: JS only signs and submits a WASM-prepared Soroban tx.
 * All proving, witness building, and tx preparation lives in the Rust WASM layer.
 */

import { rpc, xdr } from '@stellar/stellar-sdk';
import { signWalletAuthEntry, signWalletTransaction } from './wallet.js';

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function patchAuthEntries(txXdr, signedAuthEntries) {
    const env = xdr.TransactionEnvelope.fromXDR(txXdr, 'base64');

    const v1 = env.v1();
    if (!v1) {
        throw new Error('Unsupported transaction envelope (expected v1)');
    }

    const tx = v1.tx();
    const ops = tx.operations();

    const auth = signedAuthEntries.map(e => xdr.SorobanAuthorizationEntry.fromXDR(e, 'base64'));

    let patched = false;
    for (const op of ops) {
        const body = op.body();
        const invoke = body?.invokeHostFunctionOp?.();
        if (!invoke) continue;
        invoke.auth(auth);
        patched = true;
        break;
    }

    if (!patched) {
        throw new Error('No invokeHostFunction operation found to attach auth entries');
    }

    return env.toXDR('base64');
}

/**
 * Sign prepared auth entries + tx, then submit to Soroban RPC and wait for a final status.
 *
 * @param {{txXdr: string, authEntries: string[]}} prepared
 * @param {{address: string, rpcUrl: string, networkPassphrase: string}} ctx
 * @param {{onStatus?: (p: {flow?: string, stage: string, message: string, current?: number, total?: number}) => void}} [opts]
 * @returns {Promise<string>} transaction hash
 */
export async function submitPreparedSorobanTx(prepared, ctx, opts = {}) {
    const { txXdr, authEntries } = prepared || {};
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

    const signedAuthEntries = [];
    for (let i = 0; i < authEntries.length; i++) {
        const entryXdr = authEntries[i];
        emit('sign_auth', `Approve authorization (${i + 1}/${authEntries.length})…`, i + 1, authEntries.length);
        const { signedAuthEntry } = await signWalletAuthEntry(entryXdr, { address, networkPassphrase });
        if (!signedAuthEntry) throw new Error('Auth entry signature was not returned');
        signedAuthEntries.push(signedAuthEntry);
    }

    const patchedTxXdr = patchAuthEntries(txXdr, signedAuthEntries);
    emit('sign_tx', 'Approve transaction…');
    const { signedTxXdr } = await signWalletTransaction(patchedTxXdr, { address, networkPassphrase });
    if (!signedTxXdr) throw new Error('Transaction signature was not returned');

    const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
    emit('submit', 'Submitting…');
    const send = await server.sendTransaction(signedTxXdr);

    const hash = send?.hash;
    if (!hash) {
        const err = send?.errorResultXdr ? ` (errorResultXdr: ${send.errorResultXdr})` : '';
        throw new Error(`Transaction submission failed${err}`);
    }

    // Wait for a terminal state (keep it short; UI can refresh).
    for (let i = 0; i < 30; i++) {
        emit('confirm', `Confirming… (${i + 1}/30)`, i + 1, 30);
        await sleep(1_000);
        const res = await server.getTransaction(hash);
        if (res?.status === 'SUCCESS') return hash;
        if (res?.status === 'FAILED') {
            const err = res?.resultXdr ? ` (resultXdr: ${res.resultXdr})` : '';
            throw new Error(`Transaction failed${err}`);
        }
    }

    return hash;
}
