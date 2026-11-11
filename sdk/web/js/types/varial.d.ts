import type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
} from "./signer.js";

/** Varial wallet adapter for {@link Client.account}. */
export declare class VarialSigner {
  ensureReady(): Promise<void>;
  getPublicKey(): Promise<string>;
  signTransaction(
    xdr: string,
    opts?: SignOptions,
  ): Promise<SignTransactionResult>;
  signAuthEntry(xdr: string, opts?: SignOptions): Promise<SignAuthEntryResult>;
  signMessage(message: string, opts?: SignOptions): Promise<SignMessageResult>;
}
