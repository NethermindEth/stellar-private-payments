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
import type { Storage, StorageOpenOptions } from './storage.js';
import type { WalletSigner } from './signer.js';

export { default } from '../../dist/stellar_private_payments_sdk_web.js';
export {
  Account,
  PrivatePool,
  Storage,
  bootnodeRequired,
} from '../../dist/stellar_private_payments_sdk_web.js';
export type { Client as WasmClient } from '../../dist/stellar_private_payments_sdk_web.js';

export type {
  AccountOptions,
  ClientNewOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  VerifyDisclosureOptions,
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
  deriveAspUserLeaf(): Promise<string>;
  registerPublicKeys(options?: RegisterPublicKeysOptions | null): Promise<string>;
  pool(options: PoolOptions): Promise<PrivatePool>;
}

/** Deployment runtime returned by {@link Client.new}. */
export interface DeploymentClient {
  backgroundSync(): Promise<void>;
  stopBackgroundSync(): void;
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

/**
 * Probe whether the wallet RPC needs a historical-sync bootnode.
 * @returns `true` when a bootnode is required, `false` otherwise.
 */
export declare function bootnodeRequired(
  rpcUrl: string,
  storage: Storage,
): Promise<boolean>;

/**
 * Derive the ASP membership leaf from explicit public inputs.
 * @param notePublicKey `0x`-prefixed 32-byte hex
 * @param membershipBlinding `0x`-prefixed 32-byte hex field
 */
export declare function deriveAspUserLeaf(
  notePublicKey: string,
  membershipBlinding: string,
): string;

/** Walletless selective-disclosure verification (no storage / Client). */
export declare function verifySelectiveDisclosure(
  rpcUrl: string,
  receiptJson: string,
  expectedVkHash: string,
  options?: VerifyDisclosureOptions,
): Promise<DisclosureVerificationReport>;

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  new(options: ClientNewOptions): Promise<DeploymentClient>;
  contractConfig(): unknown;
};
