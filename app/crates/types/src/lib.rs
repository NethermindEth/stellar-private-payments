use serde::{Deserialize, Serialize};

// scripts/deployments.json
#[derive(Debug, Serialize, Deserialize)]
pub struct ContractConfig {
    pub network: String,
    pub deployer: String,
    pub admin: String,
    pub asp_membership: String,
    pub asp_non_membership: String,
    pub verifier: String,
    pub pool: String,
    pub initialized: bool,
}
