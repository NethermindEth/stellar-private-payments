//! Pool `transact` circuit artifact identity.

use super::{GvkMode, PolicyFlags};
use anyhow::{Result, anyhow};
use core::{fmt, str::FromStr};

const GVK_STEM_SUFFIX: &str = "_gvk_";

/// Identifies a circuit artifact.
///
/// Combines [`PolicyFlags`] with [`GvkMode`]. Non-GVK pools use plain
/// `policy_tx_2_2[_AB]` stems; GVK pools use
/// `policy_tx_2_2[_AB]_gvk_{V|T}` (`V` = view-only, `T` = traceable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitStem {
    pub policy_flags: PolicyFlags,
    pub gvk_mode: GvkMode,
}

impl CircuitStem {
    pub fn transact(policy_flags: PolicyFlags, gvk_mode: GvkMode) -> Self {
        Self {
            policy_flags,
            gvk_mode,
        }
    }

    /// Parse a stem string back into its components.
    pub fn from_string(stem: &str) -> Result<Self> {
        if let Some((policy_stem, mode_word)) = stem.rsplit_once(GVK_STEM_SUFFIX) {
            Ok(Self {
                policy_flags: PolicyFlags::from_stem(policy_stem)?,
                gvk_mode: gvk_mode_from_stem_word(mode_word)?,
            })
        } else {
            Ok(Self {
                policy_flags: PolicyFlags::from_stem(stem)?,
                gvk_mode: GvkMode::Off,
            })
        }
    }

    /// Every policy-transact stem: all flag combos × `{Off, ViewOnly,
    /// Traceable}`.
    pub fn all_transact_stems() -> Vec<Self> {
        PolicyFlags::all_flags()
            .into_iter()
            .flat_map(|policy_flags| {
                [GvkMode::Off, GvkMode::ViewOnly, GvkMode::Traceable]
                    .into_iter()
                    .map(move |gvk_mode| Self::transact(policy_flags, gvk_mode))
            })
            .collect()
    }
}

impl FromStr for CircuitStem {
    type Err = anyhow::Error;

    fn from_str(stem: &str) -> Result<Self> {
        Self::from_string(stem)
    }
}

impl fmt::Display for CircuitStem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&compose_stem_string(self.policy_flags, self.gvk_mode))
    }
}

fn compose_stem_string(policy_flags: PolicyFlags, gvk_mode: GvkMode) -> String {
    let base = policy_flags.circuit_stem();
    let Some(mode_word) = gvk_stem_word(gvk_mode) else {
        return base;
    };
    format!("{base}{GVK_STEM_SUFFIX}{mode_word}")
}

fn gvk_stem_word(mode: GvkMode) -> Option<&'static str> {
    match mode {
        GvkMode::Off => None,
        GvkMode::ViewOnly => Some("V"),
        GvkMode::Traceable => Some("T"),
    }
}

fn gvk_mode_from_stem_word(word: &str) -> Result<GvkMode> {
    match word {
        "V" => Ok(GvkMode::ViewOnly),
        "T" => Ok(GvkMode::Traceable),
        _ => Err(anyhow!("unknown GVK circuit mode word: {word}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_transact_stems_match_registry_and_round_trip() {
        let expected = [
            "policy_tx_2_2",
            "policy_tx_2_2_gvk_V",
            "policy_tx_2_2_gvk_T",
            "policy_tx_2_2_A",
            "policy_tx_2_2_A_gvk_V",
            "policy_tx_2_2_A_gvk_T",
            "policy_tx_2_2_B",
            "policy_tx_2_2_B_gvk_V",
            "policy_tx_2_2_B_gvk_T",
            "policy_tx_2_2_AB",
            "policy_tx_2_2_AB_gvk_V",
            "policy_tx_2_2_AB_gvk_T",
        ];

        let stems: Vec<_> = CircuitStem::all_transact_stems()
            .iter()
            .map(|stem| stem.to_string())
            .collect();
        assert_eq!(stems, expected);

        for stem in CircuitStem::all_transact_stems() {
            let parsed = CircuitStem::from_string(&stem.to_string()).expect("parse");
            assert_eq!(parsed, stem);
        }
    }

    #[test]
    fn parse_rejects_unknown_gvk_mode_word() {
        assert!(CircuitStem::from_string("policy_tx_2_2_A_gvk_bogus").is_err());
    }
}
