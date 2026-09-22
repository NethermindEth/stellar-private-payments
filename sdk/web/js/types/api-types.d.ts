/**
 * Public JS facade types (`js/index.js`).
 *
 * Domain types are wasm-bindgen classes from `./crates/…` (re-exported via
 * `./index.d.ts`). This module adds facade options and wrapped entry points.
 */
import type {
  ContractConfig,
  ContractsStateData,
  DisclosureVerificationReport,
  OperationalFeedItem,
  PortfolioBalance,
  PrivatePool,
  RecipientLookup,
  UserNoteSummary,
  UserPublicKeys,
} from './crates/stellar_private_payments_web.js';
import type { WalletSigner } from './signer.js';

/** Asset descriptor in deployments.json (`asset` field). */
export interface AssetDescriptorInput {
  kind: 'native' | 'classic' | 'contract';
  code?: string;
  issuer?: string;
  contractId?: string;
  symbol?: string;
}

/** Pool entry in deployments.json (`pools` array). */
export interface PoolConfigInput {
  poolContractId: string;
  tokenContractId: string;
  deploymentLedger: number;
  enabled: boolean;
  policyFlags?: string[];
  gvkMode?: string;
  gvkAuthorityPubKey?: unknown;
  asset: AssetDescriptorInput;
}

/**
 * Plain deployment config (`deployments.json` shape).
 *
 * Accepted by {@link Client.new} and parsed at the wasm boundary via serde.
 */
export interface ContractConfigInput {
  network: string;
  deployer: string;
  admin: string;
  asp_membership: string;
  asp_non_membership: string;
  verifiers: Record<string, string>;
  public_key_registry: string;
  pools: PoolConfigInput[];
}

/** Log sink targets for {@link configureTelemetry}. */
export type TelemetrySink = 'console' | 'ringBuffer' | 'both';

/** Options for {@link configureTelemetry}. */
export interface TelemetryConfig {
  level?: string;
  sink?: TelemetrySink;
  ringBufferBytes?: number;
  revealSensitive?: boolean;
}

/** Options for {@link Storage.open}. */
export interface StorageOpenOptions {
  workerUrl?: string;
}

/** Supply a random 256-bit key; preserve a recoverable wrapped copy before
 * creating the database. Do not return a wallet signature or a SEP-53 key.
 */
export type DatabaseKeyProvider = (
  databaseId: string,
  purpose: 'create' | 'open',
) => Uint8Array | Promise<Uint8Array>;

export interface EncryptedStorageOpenOptions extends StorageOpenOptions {
  keyProvider: DatabaseKeyProvider;
  /** Refuse an existing database when true; require an existing one otherwise. */
  createNew?: boolean;
}

/**
 * Worker-backed local persistence (`spp.db` on OPFS).
 *
 * Open once per page via {@link Storage.open}. Call {@link Storage.fork} for
 * additional handles (e.g. app code alongside {@link Client.new}).
 */
export interface Storage {
  fork(): Storage;
  /** Releases the database for this handle and all forks. Reopen with Storage.open/openEncrypted. */
  close(): Promise<void>;
  call(request: unknown, timeoutMs?: number): Promise<unknown>;
}

export type StorageMigrationStatus = 'copying' | 'prepared' | 'active' | 'cleaning' | 'complete' | 'aborted';

/** Owns both OPFS pools. Close all other storage users (including other tabs)
 * before opening. Retain a recoverable wrapped key before createNew.
 * After active/cleaning/complete, close this handle and use Storage.openEncrypted;
 * never reopen the stale plaintext source. finish explicitly removes that source.
 * Cleanup cannot erase browser/filesystem snapshots or external backups.
 * An operation failure closes the worker's pools; close and reopen the migration
 * handle before retrying so durable mappings are reacquired.
 * Resume requires a durable control record. For an interrupted initial create,
 * recoverMigrationSetup explicitly repairs incomplete control state using the
 * same key and unchanged plaintext source. Legacy unmarked state fails closed.
 */
export interface StorageMigration {
  status(): Promise<StorageMigrationStatus>;
  prepare(): Promise<StorageMigrationStatus>;
  activate(): Promise<StorageMigrationStatus>;
  abort(): Promise<StorageMigrationStatus>;
  /** Restart an aborted migration with the same key and current plaintext data. */
  restart(): Promise<StorageMigrationStatus>;
  finish(): Promise<StorageMigrationStatus>;
  close(): Promise<void>;
}

/** Encrypted opening requires an opt-in sqlite3mc build and uses separate OPFS storage. */
export declare const Storage: {
  /** Authenticated, consistent encrypted snapshot; does not close the storage handle. */
  exportEncrypted(storage: Storage, options: EncryptedStorageOpenOptions): Promise<Uint8Array>;
  /** Fresh destination or exact interrupted restore only. Close all storage users first. */
  restoreEncrypted(snapshot: Uint8Array, options: EncryptedStorageOpenOptions): Promise<void>;
  supportsEncryption(): boolean;
  open(options?: StorageOpenOptions | null): Promise<Storage>;
  openEncrypted(options: EncryptedStorageOpenOptions): Promise<Storage>;
  openMigration(options: EncryptedStorageOpenOptions): Promise<StorageMigration>;
  /** Repair interrupted initial setup only. Refuses established migrations and
   * any encrypted candidate. Uses the provider's 'open' purpose and ignores
   * createNew. Before any setup marker/database exists, a new key can be bound.
   * If a previous recovery finished but its response was lost, use openMigration.
   */
  recoverMigrationSetup(options: EncryptedStorageOpenOptions): Promise<StorageMigration>;
};

/** Options for {@link Client.new}. */
export interface ClientNewOptions {
  rpcUrl: string;
  /** Bindgen class or plain `deployments.json` object (round-trip safe). */
  contractConfig: ContractConfig | ContractConfigInput;
  circuitsBaseUrl: string;
  storage?: Storage;
  storageWorkerUrl?: string;
  proverWorkerUrl?: string;
  bootnodeUrl?: string;
}

/** Options for {@link Client.account}. */
export interface AccountOptions {
  networkPassphrase: string;
  userAddress?: string;
  /**
   * Defaults to `userAddress`. A value differing from `userAddress` is refused
   * before the wallet is prompted.
   */
  signerAddress?: string;
}

/** Options for {@link Account.pool}. */
export interface PoolOptions {
  poolContract: string;
}

/** Options for {@link Account.registerPublicKeys}. */
export interface RegisterPublicKeysOptions {
  notePublicKeyHex?: string;
  encryptionPublicKeyHex?: string;
}

/** Options for {@link verifySelectiveDisclosure}. */
export interface VerifyDisclosureOptions {
  contractConfig: ContractConfig | ContractConfigInput;
  circuitsBaseUrl: string;
  proverWorkerUrl?: string;
}

/** Options for {@link bootnodeRequired}. */
export interface BootnodeRequiredOptions {
  contractConfig: ContractConfig | ContractConfigInput;
}

/** Wallet session returned by {@link Client.account}. */
export interface Account {
  readonly userAddress: string;
  readonly signerAddress: string;
  portfolio(): Promise<PortfolioBalance[]>;
  userPublicKeys(): Promise<UserPublicKeys>;
  aspSecret(): Promise<string>;
  userNotes(limit: number): Promise<UserNoteSummary[]>;
  isRegistered(): Promise<boolean>;
  deriveAspUserLeaf(): Promise<string>;
  registerPublicKeys(options?: RegisterPublicKeysOptions | null): Promise<string>;
  pool(options: PoolOptions): Promise<PrivatePool>;
}

/** Deployment runtime returned by {@link Client.new}. */
export interface Client {
  backgroundSync(): Promise<void>;
  stopBackgroundSync(): void;
  sync(): Promise<void>;
  operationalFeed(limit: number): Promise<OperationalFeedItem[]>;
  contractConfig(): ContractConfig;
  account(options: AccountOptions, signer: WalletSigner): Promise<Account>;
  recipientLookup(address: string): Promise<RecipientLookup>;
  aspState(): Promise<ContractsStateData>;
  allContractsData(): Promise<ContractsStateData>;
  verifySelectiveDisclosure(
    receiptJson: string,
    expectedVkHash: string,
  ): Promise<DisclosureVerificationReport>;
}

/** Public SDK entry — worker URL defaults and optional `userAddress` resolution. */
export declare const Client: {
  new: (options: ClientNewOptions) => Promise<Client>;
};

export declare function bootnodeRequired(
  rpcUrl: string,
  storage: Storage,
  options: BootnodeRequiredOptions,
): Promise<boolean>;

export declare function deriveAspUserLeaf(
  notePublicKey: string,
  membershipBlinding: string,
): string;

export declare function verifySelectiveDisclosure(
  rpcUrl: string,
  receiptJson: string,
  expectedVkHash: string,
  options: VerifyDisclosureOptions,
): Promise<DisclosureVerificationReport>;

export declare function configureTelemetry(config?: TelemetryConfig): void;
export declare function set_log_level(level: string): void;
export declare function debugLogsEnabled(): boolean;
export declare function dump_recent_logs(): Promise<string>;

/** DOM event name emitted during in-flight pool transactions. */
export declare const TX_PROGRESS_EVENT: 'stellar-private-payments:tx-progress';

/** Payload on {@link TX_PROGRESS_EVENT} `CustomEvent.detail`. */
export interface TxProgressDetail {
  flow: string;
  stage: string;
  message: string;
  current?: number;
  total?: number;
}

/** Admin-recovered note secrets (BN254 field elements as `0x` hex). */
export interface GvkRecoveredNote {
  pk: string;
  amount: string;
  blinding: string;
}

/** Recovered note verified against an on-chain commitment. */
export interface GvkAuditedNote {
  note: GvkRecoveredNote;
  commitment: string;
}

/** One output slot from a private `transact` call. */
export interface GvkOutputSlot {
  commitment: string;
  note: GvkAuditedNote | null;
}

/** One input slot from a private `transact` call. */
export interface GvkSpentInput {
  nullifier: string;
  note: GvkAuditedNote | null;
}

/** Decrypted notes aligned with on-chain input/output slots for one private `transact` call. */
export interface GvkTxAudit {
  ledger: number;
  outputs: GvkOutputSlot[];
  inputs: GvkSpentInput[];
}
