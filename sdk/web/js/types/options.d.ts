/** Options for {@link Client.new}. */
export interface ClientNewOptions {
  rpcUrl: string;
  /**
   * Injected local persistence. When omitted, the SDK opens a default storage
   * worker (see `storageWorkerUrl`). Prefer {@link Storage.open} once per page
   * and pass the same instance (or a {@link Storage.fork}) here.
   */
  storage?: import('./storage.js').Storage;
  /** Used only when `storage` is omitted. */
  storageWorkerUrl?: string;
  /**
   * Absolute URL for the prover worker. Defaults to the package
   * `dist/workers/prover-worker.js` via `import.meta.url`.
   */
  proverWorkerUrl?: string;
  /** Optional historical-sync bootnode for retention gaps. */
  bootnodeUrl?: string;
}

/** Options for {@link DeploymentClient.account}. */
export interface AccountOptions {
  networkPassphrase: string;
  /** Optional when `signer.getPublicKey()` is implemented. */
  userAddress?: string;
}

/** Options for {@link AccountClient.pool}. */
export interface PoolOptions {
  poolContract: string;
}

/** Options for {@link AccountClient.registerPublicKeys}. */
export interface RegisterPublicKeysOptions {
  notePublicKeyHex?: string;
  encryptionPublicKeyHex?: string;
}
