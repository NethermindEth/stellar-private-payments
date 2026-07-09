//! Transact circuit entry-point names and pool policy modes.

use serde::{Deserialize, Serialize};

/// ASP policy enforced in the transact circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyMode {
    /// Allowlist + blocklist (`policy_tx_2_2_permissioned`).
    Permissioned,
    /// Open pool: blocklist only, no allowlist.
    Open,
}

impl PolicyMode {
    /// ASP allowlist proofs are required in the circuit witness.
    pub fn requires_membership_proofs(self) -> bool {
        matches!(self, PolicyMode::Permissioned)
    }

    /// ASP blocklist (non-membership) proofs are required in the circuit
    /// witness.
    pub fn requires_non_membership_proofs(self) -> bool {
        true
    }

    /// Key used in `deployments.json` `verifiers` map.
    pub fn config_key(self) -> &'static str {
        match self {
            PolicyMode::Permissioned => "permissioned",
            PolicyMode::Open => "open",
        }
    }
}

pub const POLICY_TX_2_2_PERMISSIONED: &str = "policy_tx_2_2_permissioned";
pub const POLICY_TX_2_2_OPEN: &str = "policy_tx_2_2_open";

/// Circom artifact stem for the pool's policy mode.
pub fn policy_tx_stem(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Permissioned => POLICY_TX_2_2_PERMISSIONED,
        PolicyMode::Open => POLICY_TX_2_2_OPEN,
    }
}
