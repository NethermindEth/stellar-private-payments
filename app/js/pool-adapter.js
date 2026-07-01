/**
 * Compatibility wrapper around SDK `PrivatePool` for the transactions UI.
 * Converts stroops/bigint amounts and legacy return shapes (tx hash strings).
 */

import { loadWalletKeys } from './wasm-facade.js';

const N_OUTPUTS = 2;

function stroopsToDecimal(stroops) {
    if (stroops == null) return '0';
    const v = typeof stroops === 'bigint' ? stroops : BigInt(stroops);
    const negative = v < 0n;
    const abs = (negative ? -v : v).toString().padStart(8, '0');
    const intPart = abs.slice(0, -7);
    const frac = abs.slice(-7).replace(/0+$/, '');
    const out = frac ? `${intPart}.${frac}` : intPart;
    return negative ? `-${out}` : out;
}

function txResultsToHashes(results) {
    if (results == null) return null;
    const list = Array.isArray(results) ? results : [results];
    return list.map((r) => (typeof r === 'string' ? r : r?.txHash)).filter(Boolean);
}

function normalizeOptionalHex(value) {
    if (value == null || value === '') return null;
    return String(value).trim();
}

/**
 * @param {import('stellar-private-payments-sdk').PrivatePool} sdkPool
 * @param {{ poolContractId: string, userAddress: string }} ctx
 */
export function wrapSdkPool(sdkPool, { poolContractId, userAddress }) {
    return {
        estimate(amountStroops) {
            return sdkPool.estimate(stroopsToDecimal(amountStroops));
        },

        async deposit(amountStroops, outputAmounts, _onStatus) {
            const outputs = Array.isArray(outputAmounts) ? outputAmounts : [];
            const splitDeposit =
                outputs.length >= N_OUTPUTS
                && (outputs[0] !== amountStroops || outputs[1] !== 0n);

            if (!splitDeposit) {
                const results = await sdkPool.deposit(stroopsToDecimal(amountStroops));
                return txResultsToHashes(results);
            }

            const keys = await loadWalletKeys(userAddress);
            const noteKey = keys.pubKey;
            const encKey = keys.encryptionKeypair.publicKey;
            const result = await sdkPool.transact({
                extRecipient: poolContractId,
                extAmount: stroopsToDecimal(amountStroops),
                inputNoteIds: [],
                outputAmounts: outputs.slice(0, N_OUTPUTS).map(stroopsToDecimal),
                outRecipientNoteKeysHex: [noteKey, noteKey],
                outRecipientEncKeysHex: [encKey, encKey],
            });
            return txResultsToHashes(result);
        },

        async transfer(amountStroops, noteKey, encKey, _onStatus) {
            const results = await sdkPool.transferToKeys(
                noteKey,
                encKey,
                stroopsToDecimal(amountStroops),
            );
            return txResultsToHashes(results);
        },

        async withdraw(recipient, amountStroops, _onStatus) {
            const results = await sdkPool.withdraw(
                stroopsToDecimal(amountStroops),
                recipient || undefined,
            );
            return txResultsToHashes(results);
        },

        async transact(
            extRecipient,
            extAmountStroops,
            inputNoteIds,
            outputAmounts,
            outRecipientNoteKeysHex,
            outRecipientEncKeysHex,
            _onStatus,
        ) {
            const result = await sdkPool.transact({
                extRecipient,
                extAmount: stroopsToDecimal(extAmountStroops),
                inputNoteIds: inputNoteIds ?? [],
                outputAmounts: (outputAmounts ?? []).slice(0, N_OUTPUTS).map(stroopsToDecimal),
                outRecipientNoteKeysHex: (outRecipientNoteKeysHex ?? [])
                    .slice(0, N_OUTPUTS)
                    .map(normalizeOptionalHex),
                outRecipientEncKeysHex: (outRecipientEncKeysHex ?? [])
                    .slice(0, N_OUTPUTS)
                    .map(normalizeOptionalHex),
            });
            return txResultsToHashes(result);
        },
    };
}
