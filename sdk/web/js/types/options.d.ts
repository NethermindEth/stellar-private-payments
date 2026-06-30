/** Options for {@link Client.connect}. */
export interface ConnectOptions {
  rpcUrl: string;
  networkPassphrase: string;
  /** Optional when `signer.getPublicKey()` is implemented. */
  userAddress?: string;
  storageWorkerUrl?: string;
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
