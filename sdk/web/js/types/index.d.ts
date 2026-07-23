/// <reference path="./wasm.d.ts" />

import type { PrivatePool } from '../../dist/stellar_private_payments_sdk_web.js';

import type {
  AccountOptions,
  ClientNewOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  VerifyDisclosureOptions,
} from './options.js';
import type { DisclosureVerificationReport } from './disclosure.js';
import type { Storage } from './storage.js';
import type { WalletSigner } from './signer.js';

export { default } from '../../dist/stellar_private_payments_sdk_web.js';
export { PrivatePool } from '../../dist/stellar_private_payments_sdk_web.js';
export type { Client as WasmClient } from '../../dist/stellar_private_payments_sdk_web.js';

export type {
  AccountOptions,
  ClientNewOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  VerifyDisclosureOptions,
} from './options.js';
export type { DisclosureVerificationReport } from './disclosure.js';
export { Storage, type StorageOpenOptions } from './storage.js';
export type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
  WalletSigner,
} from './signer.js';

export { FreighterSigner } from './freighter.js';

/** Wallet session returned by {@link Client.account}. */
export interface Account {
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
export interface Client {
  backgroundSync(): Promise<void>;
  stopBackgroundSync(): void;
  sync(): Promise<void>;
  operationalFeed(limit: number): Promise<unknown>;
  account(options: AccountOptions, signer: WalletSigner): Promise<Account>;
  recipientLookup(address: string): Promise<unknown>;
  aspState(): Promise<unknown>;
  allContractsData(): Promise<unknown>;
  verifySelectiveDisclosure(
    receiptJson: string,
    expectedVkHash: string,
  ): Promise<DisclosureVerificationReport>;
}

/**
 * Probe whether the wallet RPC needs a historical-sync bootnode.
 * @returns `true` when a bootnode is required, `false` otherwise.
 */
export declare function bootnodeRequired(
  rpcUrl: string,
  storage: Storage,
): Promise<boolean>;

/** Walletless selective-disclosure verification (no storage / Client). */
export declare function verifySelectiveDisclosure(
  rpcUrl: string,
  receiptJson: string,
  expectedVkHash: string,
  options?: VerifyDisclosureOptions,
): Promise<DisclosureVerificationReport>;

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  new(options: ClientNewOptions): Promise<Client>;
  contractConfig(): unknown;
};
