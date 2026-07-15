//! Transact circuit entry-point names and pool policy flags.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const POLICY_TX_2_2: &str = "policy_tx_2_2";
pub const POLICY_FLAGS_IN_SUFFIX_ORDER: &[PolicyFlag] =
    &[PolicyFlag::Allowlist, PolicyFlag::Blocklist];

const fn policy_mask(flags: &[PolicyFlag]) -> u32 {
    match flags.split_first() {
        None => 0,
        Some((head, tail)) => head.bit() | policy_mask(tail),
    }
}

pub(crate) const POLICY_MASK: u32 = policy_mask(POLICY_FLAGS_IN_SUFFIX_ORDER);

/// Bit index for a single ASP policy dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyFlag {
    Allowlist,
    Blocklist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PolicyFlags(u32);

impl PolicyFlag {
    pub const fn bit(self) -> u32 {
        match self {
            Self::Allowlist => 1 << 0,
            Self::Blocklist => 1 << 1,
        }
    }

    pub const fn letter(self) -> char {
        match self {
            Self::Allowlist => 'A',
            Self::Blocklist => 'B',
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Allowlist => "allowlist",
            Self::Blocklist => "blocklist",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        POLICY_FLAGS_IN_SUFFIX_ORDER
            .iter()
            .copied()
            .find(|flag| flag.name() == name)
            .ok_or_else(|| anyhow!("unknown policy flag '{name}'"))
    }

    fn from_letter(letter: char) -> Result<Self> {
        POLICY_FLAGS_IN_SUFFIX_ORDER
            .iter()
            .copied()
            .find(|flag| flag.letter() == letter)
            .ok_or_else(|| anyhow!("unknown policy circuit suffix letter: {letter}"))
    }
}

impl PolicyFlags {
    pub const ALLOWLIST: Self = Self(PolicyFlag::Allowlist.bit());
    pub const BLOCKLIST: Self = Self(PolicyFlag::Blocklist.bit());
    pub const EMPTY: Self = Self(0);

    pub fn from_bits(bits: u32) -> Result<Self> {
        if bits & !POLICY_MASK != 0 {
            return Err(anyhow!("unsupported policy flags: 0x{bits:x}"));
        }
        Ok(Self(bits))
    }

    /// Parse policy flags from a transact circuit artifact stem.
    pub fn from_stem(stem: &str) -> Result<Self> {
        let suffix = if stem == POLICY_TX_2_2 {
            ""
        } else {
            stem.strip_prefix("policy_tx_2_2_")
                .ok_or_else(|| anyhow!("not a policy transact stem: {stem}"))?
        };

        let mut flags = Self::EMPTY;
        for ch in suffix.chars() {
            flags = flags.with(PolicyFlag::from_letter(ch)?);
        }
        Ok(flags)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    pub fn is_valid(self) -> bool {
        self.0 & !POLICY_MASK == 0
    }

    pub fn contains(self, flag: PolicyFlag) -> bool {
        self.0 & flag.bit() != 0
    }

    pub fn with(mut self, flag: PolicyFlag) -> Self {
        self.0 |= flag.bit();
        self
    }

    pub fn requires_membership_proofs(self) -> bool {
        self.contains(PolicyFlag::Allowlist)
    }

    pub fn requires_non_membership_proofs(self) -> bool {
        self.contains(PolicyFlag::Blocklist)
    }

    pub fn circuit_stem(self) -> String {
        let suffix = self.circuit_suffix();
        if suffix.is_empty() {
            POLICY_TX_2_2.to_owned()
        } else {
            format!("{POLICY_TX_2_2}_{suffix}")
        }
    }

    /// Suffix appended to `policy_tx_2_2` for the active flag combination
    pub fn circuit_suffix(self) -> String {
        POLICY_FLAGS_IN_SUFFIX_ORDER
            .iter()
            .filter(|flag| self.contains(**flag))
            .map(|flag| flag.letter())
            .collect()
    }

    /// All `2^n` flag combinations
    pub fn all_flags() -> Vec<Self> {
        let count = 1u32 << POLICY_FLAGS_IN_SUFFIX_ORDER.len();
        (0..count)
            .map(|bits| Self::from_bits(bits).expect("combo must fit POLICY_MASK"))
            .collect()
    }

    /// Circom artifact stems for every entry in [`Self::all_flags`]
    pub fn all_stems() -> Vec<String> {
        Self::all_flags()
            .into_iter()
            .map(Self::circuit_stem)
            .collect()
    }
}

impl std::ops::BitOr for PolicyFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self((self.0 | rhs.0) & POLICY_MASK)
    }
}

impl Serialize for PolicyFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let flags: Vec<&str> = POLICY_FLAGS_IN_SUFFIX_ORDER
            .iter()
            .filter(|flag| self.contains(**flag))
            .map(|flag| flag.name())
            .collect();
        flags.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyFlags {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let flags: Vec<String> = Vec::deserialize(deserializer)?;
        let mut bits = 0u32;
        for flag in flags {
            bits |= PolicyFlag::parse(&flag)
                .map_err(serde::de::Error::custom)?
                .bit();
        }
        PolicyFlags::from_bits(bits).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_stems_match_flags() {
        for flags in PolicyFlags::all_flags() {
            let stem = flags.circuit_stem();
            assert_eq!(PolicyFlags::from_stem(&stem).expect("parse stem"), flags);
        }
        assert_eq!(
            PolicyFlags::all_stems().len(),
            PolicyFlags::all_flags().len()
        );
    }

    #[test]
    fn all_flags_covers_current_combos() {
        let flags = PolicyFlags::all_flags();
        assert_eq!(flags.len(), 4);
        assert!(flags.contains(&PolicyFlags::EMPTY));
        assert!(flags.contains(&PolicyFlags::ALLOWLIST));
        assert!(flags.contains(&PolicyFlags::BLOCKLIST));
        assert!(
            flags.contains(
                &PolicyFlags::from_bits(PolicyFlag::Allowlist.bit() | PolicyFlag::Blocklist.bit())
                    .expect("both flags")
            )
        );
    }

    #[test]
    fn circuit_suffixes_match_flag_combinations() {
        assert_eq!(PolicyFlags::EMPTY.circuit_suffix(), "");
        assert_eq!(PolicyFlags::ALLOWLIST.circuit_suffix(), "A");
        assert_eq!(PolicyFlags::BLOCKLIST.circuit_suffix(), "B");
        assert_eq!(
            PolicyFlags::from_bits(PolicyFlag::Allowlist.bit() | PolicyFlag::Blocklist.bit())
                .expect("both flags")
                .circuit_suffix(),
            "AB"
        );
    }

    #[test]
    fn circuit_stem_composes_from_flags() {
        assert_eq!(PolicyFlags::EMPTY.circuit_stem(), "policy_tx_2_2");
        assert_eq!(PolicyFlags::ALLOWLIST.circuit_stem(), "policy_tx_2_2_A");
        assert_eq!(PolicyFlags::BLOCKLIST.circuit_stem(), "policy_tx_2_2_B");
        assert_eq!(
            PolicyFlags::from_bits(PolicyFlag::Allowlist.bit() | PolicyFlag::Blocklist.bit())
                .expect("both flags")
                .circuit_stem(),
            "policy_tx_2_2_AB"
        );
    }

    #[test]
    fn from_stem_roundtrip() {
        for flags in PolicyFlags::all_flags() {
            let stem = flags.circuit_stem();
            assert_eq!(PolicyFlags::from_stem(&stem).expect("parse stem"), flags);
        }
    }

    #[test]
    fn policy_flags_serde_roundtrip() {
        let flags =
            PolicyFlags::from_bits(PolicyFlag::Allowlist.bit() | PolicyFlag::Blocklist.bit())
                .expect("both flags");
        let json = serde_json::to_string(&flags).expect("serialize");
        assert_eq!(json, r#"["allowlist","blocklist"]"#);
        let parsed: PolicyFlags = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, flags);
    }
}
