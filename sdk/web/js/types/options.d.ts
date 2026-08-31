/** Options for {@link Client.new}. */
export interface ClientNewOptions {
  rpcUrl: string;
  /** Deployment config (`deployments.json` shape). */
  contractConfig: unknown;
  /** Base URL for circuit artifacts. */
  circuitsBaseUrl: string;
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

/** Options for {@link Client.account}. */
export interface AccountOptions {
  networkPassphrase: string;
  /** Optional when `signer.getPublicKey()` is implemented. */
  userAddress?: string;
  /**
   * The account that signs the transaction, sources its envelope and pays the
   * fee. Defaults to `userAddress`, and requires `userAddress` to be supplied —
   * otherwise the note owner is resolved from the signer.
   */
  signerAddress?: string;
}

/** Options for {@link Account.pool}. */
export interface PoolOptions {
  poolContract: string;
}

/** Options for {@link Account.registerPublicKeys}. */
export interface RegisterPublicKeysOptions {
  notePublicKeyHex?: string;
  encryptionPublicKeyHex?: string;
}

/** Options for {@link verifySelectiveDisclosure}. */
export interface VerifyDisclosureOptions {
  /** Deployment config (`deployments.json` shape). */
  contractConfig: unknown;
  /** Base URL for circuit artifacts. */
  circuitsBaseUrl: string;
  proverWorkerUrl?: string;
}

/** Options for {@link bootnodeRequired}. */
export interface BootnodeRequiredOptions {
  /** Deployment config (`deployments.json` shape). */
  contractConfig: unknown;
}
