//! SDK `PolicyFlags` must match on-chain `pool::policy` encoding and semantics.

use pool::policy;
use types::{PolicyFlag, PolicyFlags};

#[test]
fn policy_flag_bits_match_contract_constants() {
    assert_eq!(PolicyFlag::Allowlist.bit(), policy::ALLOWLIST_BIT);
    assert_eq!(PolicyFlag::Blocklist.bit(), policy::BLOCKLIST_BIT);
    assert_eq!(
        PolicyFlag::Allowlist.bit() | PolicyFlag::Blocklist.bit(),
        policy::MASK
    );
}

#[test]
fn policy_flags_semantics_match_contract_for_all_combos() {
    for flags in PolicyFlags::all_flags() {
        let bits = flags.bits();

        assert!(
            policy::is_valid(bits),
            "contract rejected SDK flag combo {flags:?} (bits={bits})"
        );
        assert_eq!(
            flags.requires_membership_proofs(),
            policy::requires_membership_proofs(bits),
            "membership semantics diverged for {flags:?}"
        );
        assert_eq!(
            flags.requires_non_membership_proofs(),
            policy::requires_non_membership_proofs(bits),
            "non-membership semantics diverged for {flags:?}"
        );
    }
}
