mod contract_state;
mod conversions;
mod ext_data_hash;
mod indexer;
mod rpc;
mod signer;
mod soroban_encode;
mod submit;
mod tx_assemble;
mod tx_prepare;

pub use contract_state::{PreparedSorobanTx, StateFetcher};
pub use indexer::ContractDataStorage;
pub use rpc::{Client, Client as RpcClient};
pub use signer::{LocalSigner, Signature, auth_sign_steps, unsigned_tx_for_signing};
pub use soroban_encode::BASE_FEE;
pub use stellar_xdr::{Limits, ReadXdr, TransactionEnvelope, WriteXdr};
pub use tx_assemble::apply_simulated_resources;

/// Network passphrase of the public network.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";

/// Network passphrase of the test network.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// Network passphrase of the future network.
pub const FUTURENET_PASSPHRASE: &str = "Test SDF Future Network ; October 2022";

pub(crate) use contract_state::OnchainProofPublicInputs;
pub(crate) use conversions::{
    ParsedContractEvent, parse_event_metadata, scval_to_address_string, scval_to_bytes,
    scval_to_global_view_key_ciphertext, scval_to_optional_global_view_key_ciphertext,
    scval_to_u32, scval_to_u64, scval_to_u256,
};
pub(crate) use ext_data_hash::hash_ext_data_offchain;
pub(crate) use indexer::Indexer;
pub(crate) use rpc::Error as RpcError;
pub(crate) use submit::{TxConfirmStatus, confirm_tx, submit_tx};
pub(crate) use tx_prepare::PoolTransactInput;
