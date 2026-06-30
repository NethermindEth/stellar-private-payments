/// <reference path="./wasm.d.ts" />

import type { PrivatePool } from '../../dist/private_payments_web.js';

import type {
  ConnectOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
} from './options.js';
import type { WalletSigner } from './signer.js';

export { default } from '../../dist/private_payments_web.js';
export { PrivatePool } from '../../dist/private_payments_web.js';
export type { Client as WasmClient } from '../../dist/private_payments_web.js';

export type {
  ConnectOptions,
  PoolOptions,
  RegisterPublicKeysOptions,
} from './options.js';
export type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
  WalletSigner,
} from './signer.js';

export { FreighterSigner } from './freighter.js';

/** Account session returned by {@link Client.connect}. */
export interface AccountClient {
  initialize(): Promise<void>;
  registerPublicKeys(options?: RegisterPublicKeysOptions | null): Promise<string>;
  lookupRegisteredPublicKey(address: string): Promise<unknown>;
  allContractsData(): Promise<unknown>;
  pool(options: PoolOptions): Promise<PrivatePool>;
}

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  connect(options: ConnectOptions, signer: WalletSigner): Promise<AccountClient>;
  contractConfig(): unknown;
};
