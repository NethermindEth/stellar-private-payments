//! Global View Key (GVK) memo types.
//!
//! Data structures + serialization for the off-chain memo a pool
//! administrator uses to audit notes, mirroring the in-circuit encryption in
//! `circuits/src/globalViewKey.circom`. No encryption/decryption logic lives
//! here. See `circuits/src/test/utils/global_view_key.rs` for that.

use crate::{Field, PolicyFlags};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Current `GlobalViewKeyMemo` schema version.
pub const GLOBAL_VIEW_KEY_MEMO_VERSION: u32 = 1;

/// A Baby JubJub curve point.
///
/// Baby JubJub's base field equals BN254's scalar field, so coordinates are
/// represented with the existing [`Field`] type. This struct does not
/// validate that `(x, y)` lies on the curve; that check requires curve
/// arithmetic this crate does not depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BabyJubJubPoint {
    pub x: Field,
    pub y: Field,
}

/// One note's GVK ciphertext: the ephemeral pubkey and the three encrypted
/// fields: `(R, c1, c2, c3)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalViewKeyCiphertext {
    /// Ephemeral public key `R = r * G`.
    pub r: BabyJubJubPoint,
    /// Encrypted note public key.
    pub c1: Field,
    /// Encrypted note amount.
    pub c2: Field,
    /// Encrypted note blinding.
    pub c3: Field,
}

/// Which notes a [`GlobalViewKeyMemo`] carries ciphertexts for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GlobalViewKeyMode {
    /// Output notes only.
    ViewOnly,
    /// Input and output notes.
    Traceable,
}

/// The Global View Key memo for a single transaction.
///
/// Bundles the GVK ciphertexts for every note in the transaction under a
/// shared `nonce`. `outputs` always has one entry per output slot, in output
/// order. `inputs` is `Some` (one entry per input slot, in input order) iff
/// `mode` is [`GlobalViewKeyMode::Traceable`], and `None` for
/// [`GlobalViewKeyMode::ViewOnly`].
///
/// # Note ordering vs. the circuit
///
/// The circuit (`GvkNotes` in `circuits/src/globalViewKey.circom`)
/// binds every note's keystream to a per-note encryption index `idx` that is
/// **always** `idx = k` for input `k` and `idx = nIns + k` for output `k`,
/// regardless of mode. Its *public output array*, however, is laid out
/// differently per mode, and does not always match `idx`:
///
/// - Traceable (`encryptInputs == 1`): the array holds `nIns + nOuts` entries,
///   inputs first, so array position equals `idx` exactly.
/// - View-only (`encryptInputs == 0`): the array holds only `nOuts` entries —
///   output `k` sits at array position `k`, even though its `idx` is still
///   `nIns + k`. There is no input segment at all.
///
/// This type deliberately splits the circuit's array back into two
/// independently `0..N`-indexed fields (`inputs`, `outputs`), which follow
/// the *position* convention above, not the `idx` one. Code that talks to
/// the circuit's public inputs/outputs directly must re-derive `idx` with
/// the formula above rather than read it off the array position, since the
/// two coincide only in traceable mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GlobalViewKeyMemo {
    /// Memo schema version.
    pub version: u32,
    /// View-only vs. traceable, see field docs on [`GlobalViewKeyMemo`].
    pub mode: GlobalViewKeyMode,
    /// The administrator Baby JubJub public key `D` this memo claims to be
    /// encrypted under.
    ///
    /// This is informational only and is not verified by
    /// [`GlobalViewKeyMemo::validate`]: the memo is a portable artifact that may be
    /// inspected apart from live pool configuration. Callers that need the
    /// security guarantee must cross-check this value against the pool's
    /// registered GVK authority key themselves.
    pub admin_pub_key: BabyJubJubPoint,
    /// Per-transaction nonce bound into every ciphertext in this memo.
    pub nonce: Field,
    /// Output-note ciphertexts, one per output slot, in output order.
    pub outputs: Vec<GlobalViewKeyCiphertext>,
    /// Input-note ciphertexts, one per input slot, in input order. `Some`
    /// iff `mode == GlobalViewKeyMode::Traceable`.
    pub inputs: Option<Vec<GlobalViewKeyCiphertext>>,
}

impl GlobalViewKeyMemo {
    /// Validates schema-level invariants: version, output/input slot counts
    /// against the transaction's actual note counts, and `mode`/`inputs`
    /// consistency. Does not verify any cryptographic material.
    pub fn validate(&self, n_inputs: usize, n_outputs: usize) -> Result<()> {
        if self.version != GLOBAL_VIEW_KEY_MEMO_VERSION {
            return Err(anyhow!("Unsupported global view key memo version"));
        }
        if self.outputs.len() != n_outputs {
            return Err(anyhow!("Outputs length does not match n_outputs"));
        }
        match (self.mode, &self.inputs) {
            (GlobalViewKeyMode::ViewOnly, None) => Ok(()),
            (GlobalViewKeyMode::ViewOnly, Some(_)) => {
                Err(anyhow!("View-only memo must not carry input ciphertexts"))
            }
            (GlobalViewKeyMode::Traceable, None) => {
                Err(anyhow!("Traceable memo must carry input ciphertexts"))
            }
            (GlobalViewKeyMode::Traceable, Some(inputs)) => {
                if inputs.len() != n_inputs {
                    return Err(anyhow!("Inputs length does not match n_inputs"));
                }
                Ok(())
            }
        }
    }
}

/// Pool-level Global View Key configuration.
///
/// Orthogonal to [`PolicyFlags`] rather than a bit on it: view-only and
/// traceable are mutually exclusive (unlike allowlist/blocklist, which can be
/// combined). See [`gvk_circuit_stem`] for how the two combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GvkMode {
    /// No Global View Key encryption. Pool uses the vanilla policy-transact
    /// circuits.
    #[default]
    Off,
    /// Output notes only.
    ViewOnly,
    /// Input and output notes.
    Traceable,
}

impl GvkMode {
    /// Word used in circuit stems for this mode. `None` for [`GvkMode::Off`],
    /// which contributes no suffix at all (see [`gvk_circuit_stem`]).
    fn stem_word(self) -> Option<&'static str> {
        match self {
            GvkMode::Off => None,
            GvkMode::ViewOnly => Some("viewonly"),
            GvkMode::Traceable => Some("traceable"),
        }
    }

    fn from_stem_word(word: &str) -> Result<Self> {
        match word {
            "viewonly" => Ok(GvkMode::ViewOnly),
            "traceable" => Ok(GvkMode::Traceable),
            _ => Err(anyhow!("Unknown GVK circuit mode word: {word}")),
        }
    }
}

/// Circuit artifact stem prefix for GVK-composed policy-transact circuits,
/// e.g. `policy_tx_gvk_2_2_A_viewonly`.
const POLICY_TX_GVK_2_2: &str = "policy_tx_gvk_2_2";

/// Composes [`PolicyFlags`] and [`GvkMode`] into a circuit artifact stem.
///
/// `GvkMode::Off` maps to `policy_flags.circuit_stem()` unchanged.
///  Non-GVK pools are untouched by this function.
/// `ViewOnly`/`Traceable` produce one of the 8 stems registered in
/// `circuits/build.rs` as `POLICY_GLOBAL_VIEW_KEY_CIRCUITS`, of the shape
/// `policy_tx_gvk_2_2[_{A|B|AB}]_{viewonly|traceable}`.
pub fn gvk_circuit_stem(policy_flags: PolicyFlags, gvk_mode: GvkMode) -> String {
    let Some(mode_word) = gvk_mode.stem_word() else {
        return policy_flags.circuit_stem();
    };

    let suffix = policy_flags.circuit_suffix();
    if suffix.is_empty() {
        format!("{POLICY_TX_GVK_2_2}_{mode_word}")
    } else {
        format!("{POLICY_TX_GVK_2_2}_{suffix}_{mode_word}")
    }
}

/// Parses a GVK circuit stem produced by [`gvk_circuit_stem`] back into its
/// [`PolicyFlags`]/[`GvkMode`] components.
///
/// Only accepts stems with a GVK mode word. Use [`PolicyFlags::from_stem`]
/// for plain (non-GVK) stems.
pub fn parse_gvk_circuit_stem(stem: &str) -> Result<(PolicyFlags, GvkMode)> {
    let rest = stem
        .strip_prefix(POLICY_TX_GVK_2_2)
        .ok_or_else(|| anyhow!("Not a GVK policy transact stem: {stem}"))?;

    let (suffix, mode_word) = match rest.strip_prefix('_') {
        Some(rest) => match rest.split_once('_') {
            Some((suffix, mode_word)) => (suffix, mode_word),
            None => ("", rest),
        },
        None => return Err(anyhow!("Not a GVK policy transact stem: {stem}")),
    };

    let mode = GvkMode::from_stem_word(mode_word)?;
    let flags = if suffix.is_empty() {
        PolicyFlags::EMPTY
    } else {
        PolicyFlags::from_stem(&format!("policy_tx_2_2_{suffix}"))?
    };

    Ok((flags, mode))
}

/// All 8 GVK circuit stems registered in `circuits/build.rs` as
/// `POLICY_GLOBAL_VIEW_KEY_CIRCUITS`: every [`PolicyFlags`] combination
/// crossed with [`GvkMode::ViewOnly`] and [`GvkMode::Traceable`].
pub fn all_gvk_circuit_stems() -> Vec<String> {
    PolicyFlags::all_flags()
        .into_iter()
        .flat_map(|flags| {
            [GvkMode::ViewOnly, GvkMode::Traceable]
                .into_iter()
                .map(move |mode| gvk_circuit_stem(flags, mode))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    // Small fixed offsets over test seeds cannot overflow.
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    fn field(value: u64) -> Field {
        Field(crate::U256::from(value))
    }

    fn point(x: u64, y: u64) -> BabyJubJubPoint {
        BabyJubJubPoint {
            x: field(x),
            y: field(y),
        }
    }

    fn ciphertext(seed: u64) -> GlobalViewKeyCiphertext {
        GlobalViewKeyCiphertext {
            r: point(seed, seed + 1),
            c1: field(seed + 2),
            c2: field(seed + 3),
            c3: field(seed + 4),
        }
    }

    fn view_only_memo() -> GlobalViewKeyMemo {
        GlobalViewKeyMemo {
            version: GLOBAL_VIEW_KEY_MEMO_VERSION,
            mode: GlobalViewKeyMode::ViewOnly,
            admin_pub_key: point(1, 2),
            nonce: field(3),
            outputs: vec![ciphertext(10), ciphertext(20)],
            inputs: None,
        }
    }

    fn traceable_memo() -> GlobalViewKeyMemo {
        GlobalViewKeyMemo {
            inputs: Some(vec![ciphertext(30), ciphertext(40)]),
            ..view_only_memo_with_mode(GlobalViewKeyMode::Traceable)
        }
    }

    fn view_only_memo_with_mode(mode: GlobalViewKeyMode) -> GlobalViewKeyMemo {
        GlobalViewKeyMemo {
            mode,
            ..view_only_memo()
        }
    }

    #[test]
    fn view_only_memo_round_trips_and_validates() -> Result<()> {
        let memo = view_only_memo();
        let json = serde_json::to_string(&memo)?;
        let parsed: GlobalViewKeyMemo = serde_json::from_str(&json)?;

        assert_eq!(parsed, memo);
        parsed.validate(2, 2)?;

        Ok(())
    }

    #[test]
    fn traceable_memo_round_trips_and_validates() -> Result<()> {
        let memo = traceable_memo();
        let json = serde_json::to_string(&memo)?;
        let parsed: GlobalViewKeyMemo = serde_json::from_str(&json)?;

        assert_eq!(parsed, memo);
        parsed.validate(2, 2)?;

        Ok(())
    }

    #[test]
    fn fields_serialize_as_0x_hex_not_decimal() -> Result<()> {
        let memo = view_only_memo();
        let json = serde_json::to_string(&memo)?;

        assert!(
            json.contains(&format!("\"nonce\":\"{}\"", field(3).to_0x_hex_be())),
            "nonce should serialize as 0x-hex, got: {json}"
        );

        Ok(())
    }

    #[test]
    fn memo_rejects_unknown_fields() {
        let json = r#"{
            "version": 1,
            "unexpected": true,
            "mode": "viewOnly",
            "adminPubKey": {"x": "0x0000000000000000000000000000000000000000000000000000000000000001", "y": "0x0000000000000000000000000000000000000000000000000000000000000002"},
            "nonce": "0x0000000000000000000000000000000000000000000000000000000000000003",
            "outputs": [],
            "inputs": null
        }"#;

        assert!(serde_json::from_str::<GlobalViewKeyMemo>(json).is_err());
    }

    #[test]
    fn ciphertext_rejects_unknown_fields() {
        let json = r#"{
            "r": {"x": "0x0000000000000000000000000000000000000000000000000000000000000001", "y": "0x0000000000000000000000000000000000000000000000000000000000000002"},
            "c1": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "c2": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "c3": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "unexpected": true
        }"#;

        assert!(serde_json::from_str::<GlobalViewKeyCiphertext>(json).is_err());
    }

    #[test]
    fn point_rejects_unknown_fields() {
        let json = r#"{
            "x": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "y": "0x0000000000000000000000000000000000000000000000000000000000000002",
            "unexpected": true
        }"#;

        assert!(serde_json::from_str::<BabyJubJubPoint>(json).is_err());
    }

    #[test]
    fn validate_rejects_unsupported_version() {
        let mut memo = view_only_memo();
        memo.version = 2;

        assert!(memo.validate(2, 2).is_err());
    }

    #[test]
    fn validate_rejects_output_count_mismatch() {
        let memo = view_only_memo();

        assert!(memo.validate(2, 3).is_err());
    }

    #[test]
    fn validate_rejects_view_only_with_inputs_present() {
        let memo = GlobalViewKeyMemo {
            inputs: Some(vec![ciphertext(30)]),
            ..view_only_memo()
        };

        assert!(memo.validate(2, 2).is_err());
    }

    #[test]
    fn validate_rejects_traceable_with_missing_inputs() {
        let memo = view_only_memo_with_mode(GlobalViewKeyMode::Traceable);

        assert!(memo.validate(2, 2).is_err());
    }

    #[test]
    fn validate_rejects_traceable_input_count_mismatch() {
        let memo = traceable_memo();

        assert!(memo.validate(3, 2).is_err());
    }

    #[test]
    fn gvk_off_matches_plain_policy_stem_for_all_flag_combos() {
        for flags in crate::PolicyFlags::all_flags() {
            assert_eq!(gvk_circuit_stem(flags, GvkMode::Off), flags.circuit_stem());
        }
    }

    #[test]
    fn gvk_circuit_stem_matches_known_stems_and_round_trips() {
        let expected = [
            "policy_tx_gvk_2_2_viewonly",
            "policy_tx_gvk_2_2_traceable",
            "policy_tx_gvk_2_2_A_viewonly",
            "policy_tx_gvk_2_2_A_traceable",
            "policy_tx_gvk_2_2_B_viewonly",
            "policy_tx_gvk_2_2_B_traceable",
            "policy_tx_gvk_2_2_AB_viewonly",
            "policy_tx_gvk_2_2_AB_traceable",
        ];

        let stems = all_gvk_circuit_stems();
        assert_eq!(
            stems, expected,
            "stems must match circuits/build.rs exactly"
        );

        for stem in &stems {
            let (flags, mode) = parse_gvk_circuit_stem(stem).expect("parse known stem");
            assert_eq!(gvk_circuit_stem(flags, mode), *stem);
        }
    }

    #[test]
    fn parse_gvk_circuit_stem_rejects_non_gvk_stem() {
        assert!(parse_gvk_circuit_stem("policy_tx_2_2_A").is_err());
    }

    #[test]
    fn parse_gvk_circuit_stem_rejects_unknown_mode_word() {
        assert!(parse_gvk_circuit_stem("policy_tx_gvk_2_2_A_bogus").is_err());
    }
}
