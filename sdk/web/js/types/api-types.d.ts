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

/** Options for {@link Storage.connect}. */
export interface StorageConnectOptions {
  workerUrl?: string;
}

/**
 * What the local database needs before use: `"new"` and `"unencrypted"` need
 * a password from {@link Storage.create}, `"locked"` needs
 * {@link Storage.unlock}.
 */
export type StorageStatus = 'new' | 'unencrypted' | 'locked' | 'unlocked';

/**
 * Worker-backed local persistence in an encrypted OPFS database.
 *
 * Connect once per page via {@link Storage.connect}, then create or unlock
 * the database with the user's password. The key never leaves the storage
 * worker. Call {@link Storage.fork} for additional handles (e.g. app code
 * alongside {@link Client.new}).
 *
 * `unlock` and `changePassword` reject with an `Error` whose `code` is
 * `"wrong-password"` when the password is wrong.
 */
export interface WalletUnlockContext {
  version: 1;
  address: string;
  origin: string;
  salt: string;
}

export interface PasskeyUnlockContext {
  version: 1;
  credentialId: string;
  rpId: string;
  origin: string;
  salt: string;
}

export interface Storage {
  status(): Promise<StorageStatus>;
  /**
   * Set the first password (at least 15 characters): create the database, or
   * encrypt an earlier version's unencrypted one. Opens it.
   */
  create(password: string): Promise<void>;
  unlock(password: string): Promise<void>;
  walletContext(): Promise<WalletUnlockContext | undefined>;
  /** Low-level enrollment: secret must be derived from a verified wallet signature. */
  enrollWallet(password: string, context: WalletUnlockContext, secret: string): Promise<void>;
  unlockWallet(context: WalletUnlockContext, secret: string): Promise<void>;
  passkeyContext(): Promise<PasskeyUnlockContext | undefined>;
  /** Low-level enrollment: secret must be derived from a user-verified WebAuthn PRF assertion. */
  enrollPasskey(password: string, context: PasskeyUnlockContext, secret: string): Promise<void>;
  unlockPasskey(context: PasskeyUnlockContext, secret: string): Promise<void>;
  changePassword(current: string, next: string): Promise<void>;
  /** Delete the local database and its password, for a forgotten password. */
  reset(): Promise<void>;
  fork(): Storage;
  /** Releases the database for this handle and all forks. Connect again to reopen. */
  close(): Promise<void>;
  call(request: unknown, timeoutMs?: number): Promise<unknown>;
}

export declare const Storage: {
  connect(options?: StorageConnectOptions | null): Promise<Storage>;
};

/** Options for {@link Client.new}. */
export interface ClientNewOptions {
  rpcUrl: string;
  /** Bindgen class or plain `deployments.json` object (round-trip safe). */
  contractConfig: ContractConfig | ContractConfigInput;
  circuitsBaseUrl: string;
  /** Connected and unlocked (or created) storage. */
  storage: Storage;
  proverWorkerUrl?: string;
  bootnodeUrl?: string;
}

/** Options for {@link Client.account}. */
export interface AccountOptions {
  networkPassphrase: string;
  userAddress?: string;
  /**
   * Defaults to `userAddress`. May name a different signing account; the
   * owner still holds the notes.
   */
  signerAddress?: string;
}

/** Options for {@link Account.pool}. */
export interface PoolOptions {
  poolContract: string;
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
  privacyKeys(): Promise<UserPublicKeys>;
  derivePrivacyKeys(): Promise<UserPublicKeys>;
  aspSecret(): Promise<string>;
  userNotes(limit: number): Promise<UserNoteSummary[]>;
  isRegistered(): Promise<boolean>;
  deriveAspUserLeaf(): Promise<string>;
  registerPublicKeys(): Promise<string>;
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
