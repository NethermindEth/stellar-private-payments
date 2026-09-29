/**
 * Compile-only fixture: exercises the public type surface.
 */
import {
  Client,
  Storage,
  TX_PROGRESS_EVENT,
  type ContractConfig,
  type PoolExecuteResult,
  type PrivatePool,
} from '../index.js';

declare const rpcUrl: string;
declare const walletContext: import('../index.js').WalletUnlockContext;
declare const walletSecret: string; // Derived from a verified wallet signature.
declare const signer: import('../signer.js').WalletSigner;

async function typedConsumer(config: ContractConfig) {
  void TX_PROGRESS_EVENT;

  const storage = await Storage.connect();
  const status: import('../index.js').StorageStatus = await storage.status();
  if (status === 'locked') {
    await storage.unlockWallet(walletContext, walletSecret);
  } else if (status === 'new' || status === 'unencrypted') {
    await storage.createWallet(walletContext, walletSecret);
  } else if (status !== 'unlocked') {
    throw new Error(`Storage is ${status}`);
  }
  const client = await Client.new({
    rpcUrl,
    storage,
    contractConfig: config,
    circuitsBaseUrl: 'https://example.test/circuits/',
  });

  const cfg: ContractConfig = client.contractConfig();
  void cfg.pools[0]?.poolContractId;

  const account = await client.account({ networkPassphrase: 'Test SDF Network ; September 2015' }, signer);
  const pool: PrivatePool = await account.pool({ poolContract: config.pools[0]!.poolContractId });

  const result: PoolExecuteResult = await pool.deposit(1_000_000n);
  if (result.status === 'ok') {
    void result.hashes[0];
  } else if (result.status === 'failed') {
    void result.message;
    void result.code;
  }

  const estimate = await pool.estimate(500_000n);
  void estimate.txCount;
}

void typedConsumer;
