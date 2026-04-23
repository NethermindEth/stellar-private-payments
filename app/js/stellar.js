/**
 * Stellar helpers (UI runtime).
 *
 * Kept intentionally small: JS only signs and submits a WASM-prepared Soroban tx.
 * All proving, witness building, and tx preparation lives in the Rust WASM layer.
 */

import { rpc, xdr, contract, ScInt } from '@stellar/stellar-sdk';
import { signWalletAuthEntry, signWalletTransaction } from './wallet.js';

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

function parseHex32ToBytes(hex, what = 'hex') {
    if (typeof hex !== 'string') throw new Error(`Invalid ${what}`);
    const s = hex.trim();
    if (!s.startsWith('0x') || s.length !== 66) {
        throw new Error(`Invalid ${what} (expected 0x + 64 hex chars)`);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        const byte = Number.parseInt(s.slice(2 + i * 2, 2 + i * 2 + 2), 16);
        if (!Number.isFinite(byte)) throw new Error(`Invalid ${what}`);
        out[i] = byte;
    }
    return out;
}

function toBytes(value, what = 'bytes') {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (Array.isArray(value)) return new Uint8Array(value);
    if (value && typeof value === 'object' && typeof value.length === 'number') {
        try {
            return new Uint8Array(Array.from(value));
        } catch {
            // fall through
        }
    }
    throw new Error(`Invalid ${what}`);
}

function parseU256HexToBigInt(hex, what) {
    if (typeof hex !== 'string' || !hex.startsWith('0x')) {
        throw new Error(`Invalid ${what}`);
    }
    try {
        return BigInt(hex);
    } catch {
        throw new Error(`Invalid ${what}`);
    }
}

function toI256ScVal(value, what) {
    try {
        const bi = typeof value === 'bigint' ? value : BigInt(String(value));
        return new ScInt(bi, { type: 'i256' }).toScVal();
    } catch {
        throw new Error(`Invalid ${what}`);
    }
}

function getProvedFields(proved) {
    const proofUncompressed = proved?.proofUncompressed ?? proved?.proof_uncompressed;
    const extData = proved?.extData ?? proved?.ext_data;
    const prepared = proved?.prepared;
    return { proofUncompressed, extData, prepared };
}

function getExtDataFields(extData) {
    const recipient = extData?.recipient;
    const extAmount = extData?.ext_amount ?? extData?.extAmount;
    const encryptedOutput0 = extData?.encrypted_output0 ?? extData?.encryptedOutput0;
    const encryptedOutput1 = extData?.encrypted_output1 ?? extData?.encryptedOutput1;
    return { recipient, extAmount, encryptedOutput0, encryptedOutput1 };
}

function getPreparedPublicFields(prepared) {
    const poolRoot = prepared?.poolRoot;
    const inputNullifiers = prepared?.inputNullifiers;
    const outputCommitments = prepared?.outputCommitments;
    const publicAmount = prepared?.publicAmount;
    const extDataHashBe = prepared?.extDataHashBe;
    const aspMembershipRoot = prepared?.aspMembershipRoot;
    const aspNonMembershipRoot = prepared?.aspNonMembershipRoot;
    return {
        poolRoot,
        inputNullifiers,
        outputCommitments,
        publicAmount,
        extDataHashBe,
        aspMembershipRoot,
        aspNonMembershipRoot,
    };
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
        emit('confirm', `Confirming…`, i + 1, 30);
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

/**
 * Build, simulate, sign, and submit a pool `transact` transaction using the JS Stellar SDK.
 *
 * Expects `proved` payload from WASM prover exports (proof + ext_data + public inputs),
 * and uses `contract.Client` to produce the transaction XDR/auth entries that Freighter can sign.
 *
 * @param {any} proved
 * @param {{address: string, rpcUrl: string, networkPassphrase: string, poolContractId: string}} ctx
 * @param {{onStatus?: (p: {flow?: string, stage: string, message: string, current?: number, total?: number}) => void}} [opts]
 * @returns {Promise<string>} transaction hash
 */
export async function submitProvedPoolTransact(proved, ctx, opts = {}) {
    const { address, rpcUrl, networkPassphrase, poolContractId } = ctx || {};
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

    if (!address) throw new Error('Missing address');
    if (!rpcUrl) throw new Error('Missing rpcUrl');
    if (!networkPassphrase) throw new Error('Missing networkPassphrase');
    if (!poolContractId) throw new Error('Missing poolContractId');

    const { proofUncompressed, extData, prepared } = getProvedFields(proved);
    const proofBytes = toBytes(proofUncompressed, 'proofUncompressed');
    if (proofBytes.length !== 256) {
        throw new Error(`Invalid proofUncompressed (expected 256 bytes, got ${proofBytes.length})`);
    }

    const ext = getExtDataFields(extData);
    if (typeof ext.recipient !== 'string' || !ext.recipient) throw new Error('Invalid extData.recipient');
    const encrypted0 = toBytes(ext.encryptedOutput0, 'extData.encrypted_output0');
    const encrypted1 = toBytes(ext.encryptedOutput1, 'extData.encrypted_output1');

    const pub = getPreparedPublicFields(prepared);
    if (!pub.poolRoot) throw new Error('Invalid prepared.poolRoot');
    if (!Array.isArray(pub.inputNullifiers) || pub.inputNullifiers.length !== 2) throw new Error('Invalid prepared.inputNullifiers');
    if (!Array.isArray(pub.outputCommitments) || pub.outputCommitments.length !== 2) throw new Error('Invalid prepared.outputCommitments');

    const extDataHash = toBytes(pub.extDataHashBe, 'prepared.extDataHashBe');
    if (extDataHash.length !== 32) throw new Error(`Invalid prepared.extDataHashBe (expected 32 bytes, got ${extDataHash.length})`);

    const contractProof = {
        proof: {
            a: proofBytes.slice(0, 64),
            b: proofBytes.slice(64, 192),
            c: proofBytes.slice(192, 256),
        },
        root: parseU256HexToBigInt(pub.poolRoot, 'prepared.poolRoot'),
        input_nullifiers: [
            parseU256HexToBigInt(pub.inputNullifiers[0], 'prepared.inputNullifiers[0]'),
            parseU256HexToBigInt(pub.inputNullifiers[1], 'prepared.inputNullifiers[1]'),
        ],
        output_commitment0: parseU256HexToBigInt(pub.outputCommitments[0], 'prepared.outputCommitments[0]'),
        output_commitment1: parseU256HexToBigInt(pub.outputCommitments[1], 'prepared.outputCommitments[1]'),
        public_amount: parseU256HexToBigInt(pub.publicAmount, 'prepared.publicAmount'),
        ext_data_hash: extDataHash,
        asp_membership_root: parseU256HexToBigInt(pub.aspMembershipRoot, 'prepared.aspMembershipRoot'),
        asp_non_membership_root: parseU256HexToBigInt(pub.aspNonMembershipRoot, 'prepared.aspNonMembershipRoot'),
    };

    const contractExtData = {
        encrypted_output0: encrypted0,
        encrypted_output1: encrypted1,
        ext_amount: toI256ScVal(ext.extAmount, 'extData.ext_amount'),
        recipient: ext.recipient,
    };

    emit('build_tx', 'Simulating & building…');
    const client = await contract.Client.from({
        rpcUrl,
        networkPassphrase,
        publicKey: address,
        contractId: poolContractId,
        signTransaction: async (transactionXdr, extra = {}) => {
            emit('sign_tx', 'Approve transaction…');
            return signWalletTransaction(transactionXdr, {
                address,
                networkPassphrase,
                ...extra,
            });
        },
        signAuthEntry: async (entryXdr, extra = {}) => {
            emit('sign_auth', 'Approve authorization…');
            return signWalletAuthEntry(entryXdr, {
                address,
                networkPassphrase,
                ...extra,
            });
        },
    });

    const tx = await client.transact({
        proof: contractProof,
        ext_data: contractExtData,
        sender: address,
    });

    emit('submit', 'Submitting…');
    const sent = await tx.signAndSend();
    const hash =
        sent?.sendTransactionResponse?.hash ||
        sent?.hash ||
        sent?.result?.hash ||
        null;
    if (!hash) {
        throw new Error('Transaction submission failed');
    }

    // Wait for a terminal state (keep it short; UI can refresh).
    const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
    for (let i = 0; i < 30; i++) {
        emit('confirm', `Confirming…`, i + 1, 30);
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

/**
 * Register the caller's public keys in the Pool contract address book.
 *
 * @param {{address: string, rpcUrl: string, networkPassphrase: string, poolContractId: string, notePublicKeyHex: string, encryptionPublicKeyHex: string}} ctx
 * @param {{onStatus?: (p: {flow?: string, stage: string, message: string, current?: number, total?: number}) => void}} [opts]
 * @returns {Promise<string>} transaction hash
 */
export async function submitPublicKeyRegistration(ctx, opts = {}) {
    const {
        address,
        rpcUrl,
        networkPassphrase,
        poolContractId,
        notePublicKeyHex,
        encryptionPublicKeyHex,
    } = ctx || {};

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

    if (!address) throw new Error('Missing address');
    if (!rpcUrl) throw new Error('Missing rpcUrl');
    if (!networkPassphrase) throw new Error('Missing networkPassphrase');
    if (!poolContractId) throw new Error('Missing poolContractId');

    const noteKey = parseHex32ToBytes(notePublicKeyHex, 'note public key');
    const encryptionKey = parseHex32ToBytes(encryptionPublicKeyHex, 'encryption public key');

    emit('build_tx', 'Simulating & building…');
    const client = await contract.Client.from({
        rpcUrl,
        networkPassphrase,
        publicKey: address,
        contractId: poolContractId,
        signTransaction: async (transactionXdr, extra = {}) => {
            emit('sign_tx', 'Approve transaction…');
            return signWalletTransaction(transactionXdr, {
                address,
                networkPassphrase,
                ...extra,
            });
        },
        signAuthEntry: async (entryXdr, extra = {}) => {
            emit('sign_auth', 'Approve authorization…');
            return signWalletAuthEntry(entryXdr, {
                address,
                networkPassphrase,
                ...extra,
            });
        },
    });

    const tx = await client.register({
        account: {
            owner: address,
            encryption_key: encryptionKey,
            note_key: noteKey,
        },
    });

    emit('submit', 'Submitting…');
    const sent = await tx.signAndSend();
    const hash =
        sent?.sendTransactionResponse?.hash ||
        sent?.hash ||
        sent?.result?.hash ||
        null;
    if (!hash) throw new Error('Transaction submission failed');

    // Wait for a terminal state (keep it short; UI can refresh).
    const server = new rpc.Server(rpcUrl, { allowHttp: rpcUrl.startsWith('http://') });
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
