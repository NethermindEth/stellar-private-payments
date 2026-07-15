/// <reference path="./wasm.d.ts" />

import type { PrivatePool } from '../../dist/stellar_private_payments_sdk_web.js';

import type {
  AccountOptions,
  ClientNewOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  SyncOptions,
} from './options.js';
import type { DisclosureVerificationReport } from './disclosure.js';
import type { Storage, StorageOpenOptions } from './storage.js';
import type { WalletSigner } from './signer.js';

export { default } from '../../dist/stellar_private_payments_sdk_web.js';
export { Account, PrivatePool, Storage } from '../../dist/stellar_private_payments_sdk_web.js';
export type { Client as WasmClient } from '../../dist/stellar_private_payments_sdk_web.js';

export type {
  AccountOptions,
  ClientNewOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  SyncOptions,
} from './options.js';
export type { DisclosureVerificationReport } from './disclosure.js';
export type { StorageOpenOptions } from './storage.js';
export type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
  WalletSigner,
} from './signer.js';

export { FreighterSigner } from './freighter.js';

/** Wallet session returned by {@link DeploymentClient.account}. */
export interface AccountClient {
  readonly userAddress: string;
  portfolio(): Promise<unknown>;
  userPublicKeys(): Promise<unknown>;
  aspSecret(): Promise<string>;
  userNotes(limit: number): Promise<unknown>;
  isRegistered(): Promise<boolean>;
  deriveAspUserLeaf(options?: DeriveAspUserLeafOptions | null): Promise<string>;
  registerPublicKeys(options?: RegisterPublicKeysOptions | null): Promise<string>;
  pool(options: PoolOptions): Promise<PrivatePool>;
}

export interface DeriveAspUserLeafOptions {
  notePublicKey?: string;
  membershipBlinding?: string;
}

/** Deployment runtime returned by {@link Client.new}. */
export interface DeploymentClient {
  checkSync(options?: SyncOptions | null): Promise<string | null>;
  startSync(options?: SyncOptions | null): Promise<void>;
  sync(): Promise<void>;
  operationalFeed(limit: number): Promise<unknown>;
  account(options: AccountOptions, signer: WalletSigner): Promise<AccountClient>;
  recipientLookup(address: string): Promise<unknown>;
  aspState(): Promise<unknown>;
  allContractsData(): Promise<unknown>;
  verifySelectiveDisclosure(
    receiptJson: string,
    expectedVkHash: string,
  ): Promise<DisclosureVerificationReport>;
}

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  new(options: ClientNewOptions): Promise<DeploymentClient>;
  contractConfig(): unknown;
};
