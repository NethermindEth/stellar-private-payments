use types::ContractConfig;

// TODO make it dependent on the network during the compilation
const DEPLOYMENT: &str = include_str!("../../../deployments/testnet/deployments.json");

/// Returns the statically-embedded contracts deployment configuration.
///
/// This is intentionally compiled-in (via `include_str!`) to prevent runtime
/// misconfiguration of critical identifiers like contract IDs and the
/// deployment ledger.
pub(crate) fn deployment_config() -> anyhow::Result<ContractConfig> {
    Ok(serde_json::from_str(DEPLOYMENT)?)
}
