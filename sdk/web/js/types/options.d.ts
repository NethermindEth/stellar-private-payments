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
}

/** Options for {@link AccountClient.checkEventSync} and {@link AccountClient.startEventSync}. */
export interface EventSyncOptions {
  bootnodeUrl?: string;
}

/** Options for {@link AccountClient.initialize}. */
export interface InitializeOptions {
  networkPassphrase: string;
  /** Optional when `signer.getPublicKey()` is implemented. */
  userAddress?: string;
  proverWorkerUrl?: string;
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

/** Options for {@link AccountClient.verifySelectiveDisclosure}. */
export interface VerifyDisclosureOptions {
  proverWorkerUrl?: string;
}
