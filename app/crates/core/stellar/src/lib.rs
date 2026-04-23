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

/// Returns the statically-embedded contracts deployment configuration.
///
/// This is intentionally compiled-in (via `include_str!`) to prevent runtime
/// misconfiguration of critical identifiers like contract IDs and the
/// deployment ledger.
pub fn deployment_config() -> anyhow::Result<types::ContractConfig> {
    Ok(serde_json::from_str(DEPLOYMENT)?)
}
