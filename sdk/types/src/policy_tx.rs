//! Transact circuit entry-point names and pool policy modes.

use serde::{Deserialize, Serialize};

/// ASP policy enforced in the transact circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PolicyMode {
    /// Unrestricted pool transact (`policy_tx_2_2_open`).
    Open,
    /// Allowlist only (`policy_tx_2_2_allowlist`).
    Allowlist,
    /// Blocklist only (`policy_tx_2_2_blocklist`).
    Blocklist,
    /// Allowlist + blocklist (`policy_tx_2_2_both`).
    Both,
}

impl PolicyMode {
    /// ASP allowlist proofs are required in the circuit witness.
    pub fn requires_membership_proofs(self) -> bool {
        matches!(self, PolicyMode::Allowlist | PolicyMode::Both)
    }

    /// ASP blocklist (non-membership) proofs are required in the circuit
    /// witness.
    pub fn requires_non_membership_proofs(self) -> bool {
        matches!(self, PolicyMode::Blocklist | PolicyMode::Both)
    }

    /// Key used in `deployments.json` `verifiers` map.
    pub fn config_key(self) -> &'static str {
        match self {
            PolicyMode::Open => "open",
            PolicyMode::Allowlist => "allowlist",
            PolicyMode::Blocklist => "blocklist",
            PolicyMode::Both => "both",
        }
    }
}

pub const POLICY_TX_2_2_OPEN: &str = "policy_tx_2_2_open";
pub const POLICY_TX_2_2_ALLOWLIST: &str = "policy_tx_2_2_allowlist";
pub const POLICY_TX_2_2_BLOCKLIST: &str = "policy_tx_2_2_blocklist";
pub const POLICY_TX_2_2_BOTH: &str = "policy_tx_2_2_both";

/// Circom artifact stem for the pool's policy mode.
pub fn policy_tx_stem(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Open => POLICY_TX_2_2_OPEN,
        PolicyMode::Allowlist => POLICY_TX_2_2_ALLOWLIST,
        PolicyMode::Blocklist => POLICY_TX_2_2_BLOCKLIST,
        PolicyMode::Both => POLICY_TX_2_2_BOTH,
    }
}

/// All policy transact circuit stems.
pub const ALL_POLICY_TX_STEMS: &[&str] = &[
    POLICY_TX_2_2_OPEN,
    POLICY_TX_2_2_ALLOWLIST,
    POLICY_TX_2_2_BLOCKLIST,
    POLICY_TX_2_2_BOTH,
];
