// wasm-bindgen domain types (generated on build; stubbed pre-build).
export type {
  AdminState,
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
  DisclosureVerificationReport,
  GlobalViewKeyCiphertext,
  GvkAudit,
  GvkAuthority,
  NoteKeyOwner,
  NoteKeyOwnerLookup,
  OperationalFeedItem,
  OperatorCall,
  PoolConfigEntry,
  PoolEstimate,
  PoolExecuteResult,
  PoolInfo,
  PortfolioBalance,
  PrivatePool,
  PublicKeyEntry,
  RecipientLookup,
  UnsignedOperatorCall,
  UserNoteSummary,
  UserPublicKeys,
  VerifierEntry,
} from './crates/stellar_private_payments_web.js';

export {
  AllowlistOperator,
  BlocklistOperator,
  DisclosureRequest,
  parseTokenAmount,
  PoolAdmin,
  ProverBridge,
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
