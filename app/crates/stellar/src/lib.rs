mod rpc;
mod conversions;
mod indexer;
mod contract_state;
mod contract_events;

pub use indexer::{ContractDataStorage, Indexer};
pub use contract_state::StateFetcher;

const DEPLOYMENT: &str = include_str!("../../../../scripts/deployments.json");
