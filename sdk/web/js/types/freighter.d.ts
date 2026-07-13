import type { SignAuthEntryResult, SignMessageResult, SignOptions, SignTransactionResult } from './signer.js';

/** Freighter wallet adapter for {@link DeploymentClient.account}. */
export declare class FreighterSigner {
  ensureReady(): Promise<void>;
  getPublicKey(): Promise<string>;
  signTransaction(xdr: string, opts?: SignOptions): Promise<SignTransactionResult>;
  signAuthEntry(xdr: string, opts?: SignOptions): Promise<SignAuthEntryResult>;
  signMessage(message: string, opts?: SignOptions): Promise<SignMessageResult>;
}
