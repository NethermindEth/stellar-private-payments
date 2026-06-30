/// <reference path="./wasm.d.ts" />

import type { PrivatePool } from '../../dist/private_payments_web.js';

import type {
  ClientNewOptions,
  InitializeOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  EventSyncOptions,
} from './options.js';
import type { Storage, StorageOpenOptions } from './storage.js';
import type { WalletSigner } from './signer.js';

export { default } from '../../dist/private_payments_web.js';
export { PrivatePool, Storage } from '../../dist/private_payments_web.js';
export type { Client as WasmClient } from '../../dist/private_payments_web.js';

export type {
  ClientNewOptions,
  InitializeOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
  EventSyncOptions,
} from './options.js';
export type { StorageOpenOptions } from './storage.js';
export type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
  WalletSigner,
} from './signer.js';

export { FreighterSigner } from './freighter.js';

/** Account session returned by {@link Client.new}. */
export interface AccountClient {
  checkEventSync(options?: EventSyncOptions | null): Promise<string | null>;
  startEventSync(options?: EventSyncOptions | null): Promise<void>;
  initialize(options: InitializeOptions, signer: WalletSigner): Promise<void>;
  registerPublicKeys(options?: RegisterPublicKeysOptions | null): Promise<string>;
  lookupRegisteredPublicKey(address: string): Promise<unknown>;
  allContractsData(): Promise<unknown>;
  pool(options: PoolOptions): Promise<PrivatePool>;
}

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  new(options: ClientNewOptions): Promise<AccountClient>;
  contractConfig(): unknown;
};
