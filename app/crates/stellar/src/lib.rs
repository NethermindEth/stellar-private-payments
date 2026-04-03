mod rpc;
mod conversions;
mod indexer;
mod contract_state;

pub use indexer::{ContractDataStorage, Indexer};
pub use contract_state::StateFetcher;
pub use conversions::*;

// TODO make it dependent on the network during the compilation
const DEPLOYMENT: &str = include_str!("../../../../scripts/deployments.json");
