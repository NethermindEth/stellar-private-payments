mod rpc;
mod conversions;
mod indexer;
mod contract_state;
mod ext_data_hash;

pub use indexer::{ContractDataStorage, Indexer};
pub use contract_state::StateFetcher;
pub use conversions::*;
pub use ext_data_hash::hash_ext_data_offchain;

// TODO make it dependent on the network during the compilation
const DEPLOYMENT: &str = include_str!("../../../../scripts/deployments.json");
