mod contract_state;
mod conversions;
mod ext_data_hash;
mod indexer;
mod rpc;

pub use contract_state::{OnchainProofPublicInputs, PreparedSorobanTx, StateFetcher};
pub use conversions::*;
pub use ext_data_hash::hash_ext_data_offchain;
pub use indexer::{ContractDataStorage, Indexer};

// TODO make it dependent on the network during the compilation
const DEPLOYMENT: &str = include_str!("../../../../../deployments/testnet/deployments.json");
