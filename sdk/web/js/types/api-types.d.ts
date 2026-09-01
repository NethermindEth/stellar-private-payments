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

/**
 * Worker-backed local persistence (`spp.db` on OPFS).
 *
 * Open once per page via {@link Storage.open}. Call {@link Storage.fork} for
 * additional handles (e.g. app code alongside {@link Client.new}).
 */
export interface Storage {
  fork(): Storage;
  call(request: unknown, timeoutMs?: number): Promise<unknown>;
}

/** Package entry: `Storage.open()` only (instance methods live on the handle). */
export declare const Storage: {
  open(options?: StorageOpenOptions | null): Promise<Storage>;
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
