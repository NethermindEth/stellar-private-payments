import { appStorage } from '../wasm-facade.js';

// Per-(address, pool) operation history persisted in the SQLite storage
// (`user_operations` table) via the storage worker. Records operations the user
// performs in this app (deposit / sent / withdraw / advanced).
export const OpHistory = {
    async record(address, poolId, { type, amount, direction, counterparty, hashes } = {}) {
        if (!address || !poolId) return;
        const txHash = Array.isArray(hashes) && hashes.length ? hashes[hashes.length - 1] : null;
        try {
            await appStorage().recordOperation({
                address,
                pool_contract_id: poolId,
                op_type: type || 'Operation',
                amount: amount != null ? String(amount) : '0',
                direction: direction || 'none',
                counterparty: counterparty || null,
                tx_hash: txHash,
            });
        } catch (error) {
            console.warn('[OpHistory] record failed:', error);
        }
    },

    async list(address, poolId, limit = 10) {
        if (!address || !poolId) return [];
        try {
            const ops = await appStorage().listOperations(address, poolId, limit);
            return Array.isArray(ops) ? ops : [];
        } catch (error) {
            console.warn('[OpHistory] list failed:', error);
            return [];
        }
    },
};
