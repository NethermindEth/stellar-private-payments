/** Options passed as the last argument to wallet sign methods (injected by WASM). */
export interface SignOptions {
  address?: string;
  networkPassphrase?: string;
}

export interface SignMessageResult {
  signedMessage: string;
  signerAddress: string;
}

export interface SignTransactionResult {
  signedTxXdr: string;
  signerAddress: string;
}

export interface SignAuthEntryResult {
  signedAuthEntry: string;
  signerAddress: string;
}

/**
 * Wallet adapter for {@link Client.account}.
 *
 * Must expose `signMessage`, `signTransaction`, and `signAuthEntry`.
 * Optional `getPublicKey` lets the JS wrapper resolve `userAddress`.
 */
export interface WalletSigner {
  signMessage(message: string, opts?: SignOptions): Promise<SignMessageResult>;
  signTransaction(xdr: string, opts?: SignOptions): Promise<SignTransactionResult>;
  signAuthEntry(xdr: string, opts?: SignOptions): Promise<SignAuthEntryResult>;
  getPublicKey?(): Promise<string>;
}
