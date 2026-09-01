// wasm-bindgen domain types (generated on build; stubbed pre-build).
export type {
  AspMembership,
  AspNonMembership,
  AssetDescriptor,
  BabyJubJubPoint,
  ContractConfig,
  ContractsStateData,
  DisclosureCircuitMetadata,
  DisclosureContext,
  DisclosurePublicInputs,
  DisclosureReceipt,
  DisclosureRequest,
  DisclosureVerificationReport,
  GlobalViewKeyCiphertext,
  OperationalFeedItem,
  PoolConfigEntry,
  PoolEstimate,
  PoolInfo,
  PortfolioBalance,
  PublicKeyEntry,
  RecipientLookup,
  UserNoteSummary,
  UserPublicKeys,
  VerifierEntry,
} from './crates/stellar_private_payments_web.js';

export {
  PoolExecuteResult,
  PrivatePool,
  default,
} from './crates/stellar_private_payments_web.js';

// JS facade (`js/index.js`) — options and wrapped session entry points.
export * from './api-types.js';

export type {
  SignAuthEntryResult,
  SignMessageResult,
  SignOptions,
  SignTransactionResult,
  WalletSigner,
} from './signer.js';

export type {
  Client as WasmClient,
  Account as WasmAccount,
  Storage as WasmStorage,
} from './crates/stellar_private_payments_web.js';
