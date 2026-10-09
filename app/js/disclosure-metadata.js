import { tokenLabel } from './ui/notes-view.js';

export function createDisclosureMetadata(loadConfig, readDecimals, onUpdated) {
  let revision = 0;
  let value = { decimals: null, symbol: 'Token' };
  return {
    get value() { return value; },
    async refresh(rpcUrl, poolId, network) {
      const request = ++revision;
      value = { decimals: null, symbol: 'Token' };
      onUpdated();
      try {
        const config = await loadConfig();
        if (config.network !== network) throw new Error('Receipt network differs from deployment');
        const pool = config.pools.find(pool => pool.poolContractId === poolId);
        if (!pool) throw new Error('Receipt pool is not in the deployment');
        const decimals = await readDecimals(rpcUrl, pool.tokenContractId);
        if (request !== revision) return;
        value = { decimals, symbol: tokenLabel(pool) };
        onUpdated();
      } catch (error) {
        if (request === revision) console.warn('Disclosure token precision unavailable:', error);
      }
    },
  };
}
