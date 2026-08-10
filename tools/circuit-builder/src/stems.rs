//! Circuit entry-point names that ship Groth16 key material.

use types::PolicyFlags;

const SELECTIVE_DISCLOSURE_CIRCUITS: &[&str] = &[
    "selectiveDisclosure_1",
    "selectiveDisclosure_2",
    "selectiveDisclosure_3",
    "selectiveDisclosure_4",
];

/// Policy transaction circuits combined with Global View Key encryption. Each
/// of the 4 ASP policy configs is offered in view-only and traceable modes.
const POLICY_GLOBAL_VIEW_KEY_CIRCUITS: &[&str] = &[
    "policy_tx_gvk_2_2_viewonly",
    "policy_tx_gvk_2_2_traceable",
    "policy_tx_gvk_2_2_A_viewonly",
    "policy_tx_gvk_2_2_A_traceable",
    "policy_tx_gvk_2_2_B_viewonly",
    "policy_tx_gvk_2_2_B_traceable",
    "policy_tx_gvk_2_2_AB_viewonly",
    "policy_tx_gvk_2_2_AB_traceable",
];

/// The stems that take part in Groth16 key generation.
///
/// Requirement, not possession: all 16 are generated on request, but only the 8
/// production stems have key material committed under
/// `deployments/testnet/circuit_keys`. The `policy_tx_gvk_*` stems are absent
/// from the key manifest for that reason and that is expected.
pub fn requiring_keys() -> Vec<String> {
    let mut circuits = PolicyFlags::all_stems();
    circuits.extend(
        SELECTIVE_DISCLOSURE_CIRCUITS
            .iter()
            .map(|stem| (*stem).to_owned()),
    );
    circuits.extend(
        POLICY_GLOBAL_VIEW_KEY_CIRCUITS
            .iter()
            .map(|stem| (*stem).to_owned()),
    );
    circuits
}
