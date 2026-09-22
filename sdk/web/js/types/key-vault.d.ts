import type { DatabaseKeyProvider } from './api-types.js';

export interface PasswordKeyEnvelope {
  salt: string;
  iterations: number;
  iv: string;
  ciphertext: string;
}
export interface PasskeyKeyEnvelope {
  credentialId: string;
  prfSalt: string;
  origin: string;
  rpId: string;
  iv: string;
  ciphertext: string;
}
export interface WrappedDatabaseKey {
  version: 1;
  databaseId: string;
  vaultId: string;
  revision: number;
  password: PasswordKeyEnvelope;
  passkey: PasskeyKeyEnvelope | null;
  /** Optional for backwards compatibility with password/passkey-only records. */
  wallet?: { address: string; origin: string; salt: string; iv: string; ciphertext: string } | null;
}
export interface DatabaseWalletSigner {
  getPublicKey(): Promise<string>;
  signMessage(message: string, options: { address: string }): Promise<{ signedMessage: string; signerAddress?: string }>;
}
/** Stores encrypted envelopes only. write must atomically compare and replace
 * the complete expected record, and resolve only after durable commit.
 */
export interface DatabaseKeyStore {
  read(id: string): Promise<WrappedDatabaseKey | null>;
  write(id: string, next: WrappedDatabaseKey, expected: WrappedDatabaseKey | null): Promise<void>;
}
export declare class IndexedDbKeyStore implements DatabaseKeyStore {
  constructor(name?: string);
  read(id: string): Promise<WrappedDatabaseKey | null>;
  write(id: string, next: WrappedDatabaseKey, expected: WrappedDatabaseKey | null): Promise<void>;
}
export declare class KeyVaultError extends Error { readonly code: string; }
/** Caller owns this unlocked session. Close SQLite and all users before lock().
 * lock clears this provider's bytes; it cannot clear a key already held by SQLite.
 */
export interface DatabaseKeySession {
  readonly keyProvider: DatabaseKeyProvider;
  lock(): void;
}
/** Explicit key provisioning; never auto-creates or replaces a missing key.
 * Passwords require 15–1024 characters at creation/change. Wrapped records need
 * backup along with the database: deleting them loses access even with a password.
 * Password changes/removal of a passkey do not revoke saved older envelopes.
 * Passkeys require PRF support and user verification; unsupported or cancelled
 * requests leave the password wrapper unchanged. Enrollment may leave an unused
 * credential in the authenticator if later PRF or persistence steps fail.
 * No protection against active same-origin script compromise after unlock.
 */
export declare class DatabaseKeyVault {
  constructor(options?: {
    databaseId?: string;
    store?: DatabaseKeyStore;
    credentials?: Pick<CredentialsContainer, 'create' | 'get'>;
    origin?: string;
  });
  status(): Promise<{ exists: boolean; passkey: boolean; wallet?: boolean; walletAddress?: string; revision?: number }>;
  /** Persist the wrapped random key BEFORE creating the encrypted database.
   * If database creation fails, retain this record and retry with unlockPassword.
   */
  createPassword(password: string): Promise<DatabaseKeySession>;
  unlockPassword(password: string): Promise<DatabaseKeySession>;
  changePassword(oldPassword: string, newPassword: string): Promise<void>;
  addPasskey(password: string): Promise<void>;
  unlockPasskey(): Promise<DatabaseKeySession>;
  resetPasswordWithPasskey(newPassword: string): Promise<void>;
  /** Removes the local wrapper, not the credential stored in Proton/another provider. */
  removePasskey(password: string): Promise<void>;
  /** Two dedicated SEP-53 signing requests must reproduce the wrapping key.
   * Password recovery is retained. Wallet signatures must never be disclosed.
   * The wrapper is bound to origin, account and this vault; backups made before
   * enrollment retain password recovery but do not gain wallet unlock.
   */
  addWallet(password: string, signer: DatabaseWalletSigner): Promise<void>;
  unlockWallet(signer: DatabaseWalletSigner): Promise<DatabaseKeySession>;
  /** Removes only this record's wrapper; older backups are unaffected. */
  removeWallet(password: string): Promise<void>;
}
