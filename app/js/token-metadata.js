export async function readDisplayDecimals(session) {
  try {
    return await session.tokenDecimals();
  } catch (error) {
    console.warn('Token precision unavailable; displaying base units:', error);
    return null;
  }
}

export async function refreshTokenDecimals(pools, account, isCurrent, onUpdated) {
  await Promise.all(pools.map(async pool => {
    try {
      const session = await account.pool({ poolContract: pool.poolContractId });
      const decimals = await readDisplayDecimals(session);
      if (!isCurrent()) return;
      if (pool.decimals !== decimals) {
        pool.decimals = decimals;
        onUpdated();
      }
    } catch (error) {
      if (isCurrent()) console.warn(`Token precision unavailable for ${pool.poolContractId}:`, error);
    }
  }));
}

export function requireSamePool(pool, currentPool) {
  if (!pool || currentPool !== pool) {
    throw new Error('Pool changed. Review the amount and try again.');
  }
}

export async function resolveAmountContext(pool, account, currentPool, onUpdated) {
  if (!pool) throw new Error('Select a pool first');
  const session = await account.pool({ poolContract: pool.poolContractId });
  const decimals = await session.tokenDecimals();
  requireSamePool(pool, currentPool());
  if (pool.decimals !== decimals) {
    pool.decimals = decimals;
    onUpdated();
  }
  return { pool, decimals };
}
