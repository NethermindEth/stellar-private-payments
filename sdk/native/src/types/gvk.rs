//! Global View Key (GVK) memo types.
//!
//! Data structures + serialization for the off-chain memo a pool
//! admin uses to audit notes, mirroring the in-circuit encryption in
//! `circuits/src/globalViewKey.circom`. Encryption and decryption live in
//! [`crate::zk::gvk`].

use super::{Field, PolicyFlags, PoolConfigEntry};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

/// Current `GlobalViewKeyMemo` schema version.
pub const GLOBAL_VIEW_KEY_MEMO_VERSION: u32 = 1;

/// A Baby JubJub curve point.
///
/// Baby JubJub's base field equals BN254's scalar field, so coordinates are
/// represented with the existing [`Field`] type. Deserialization does not
/// validate that `(x, y)` lies on the curve; callers using these coordinates
/// in curve arithmetic must handle invalid points via [`crate::zk::babyjub`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The admin Baby JubJub public key `D` this memo claims to be
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
/// combined). See [`CircuitStem`] for how the two combine.
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
    /// Value stored under `pool-gvk`'s `DataKey::GvkMode`, matching
    /// `pool_gvk::gvk::{VIEW_ONLY, TRACEABLE}`. `None` for [`GvkMode::Off`],
    /// which has no on-chain discriminant at all: a `contracts/pool`
    /// deployment simply has no `GvkMode` storage key.
    ///
    /// Written out explicitly rather than derived from the enum's declaration
    /// order, so reordering the variants cannot silently change the mapping.
    pub fn on_chain_value(self) -> Option<u32> {
        match self {
            GvkMode::Off => None,
            GvkMode::ViewOnly => Some(1),
            GvkMode::Traceable => Some(2),
        }
    }

    /// Inverse of [`GvkMode::on_chain_value`]. `None` input means the pool has
    /// no `GvkMode` key, i.e. [`GvkMode::Off`]; an unrecognized value is an
    /// error rather than a silent [`GvkMode::Off`].
    pub fn from_on_chain_value(value: Option<u32>) -> Result<Self> {
        match value {
            None => Ok(GvkMode::Off),
            Some(1) => Ok(GvkMode::ViewOnly),
            Some(2) => Ok(GvkMode::Traceable),
            Some(other) => Err(anyhow!("unknown on-chain GVK mode: {other}")),
        }
    }
}

/// Composes [`PolicyFlags`] and [`GvkMode`] into a circuit artifact file stem.
///
/// Prefer [`CircuitStem::transact`] and [`ToString`].
pub fn gvk_circuit_stem(policy_flags: PolicyFlags, gvk_mode: GvkMode) -> String {
    super::CircuitStem::transact(policy_flags, gvk_mode).to_string()
}

/// Parses a GVK circuit stem back into its components.
///
/// Only accepts stems with a GVK mode word. Prefer [`CircuitStem::from_string`]
/// for plain (non-GVK) stems too.
pub fn parse_gvk_circuit_stem(stem: &str) -> Result<(PolicyFlags, GvkMode)> {
    let parsed = super::CircuitStem::from_string(stem)?;
    if parsed.gvk_mode == GvkMode::Off {
        return Err(anyhow!("not a GVK policy transact stem: {stem}"));
    }
    Ok((parsed.policy_flags, parsed.gvk_mode))
}

/// Ensure `d_priv` derives the GVK authority public key declared for `pool`
pub fn validate_gvk_authority_key(d_priv: &Field, pool: &PoolConfigEntry) -> Result<()> {
    let configured = pool.gvk_authority_pub_key.as_ref().ok_or_else(|| {
        anyhow!(
            "pool {} has no gvkAuthorityPubKey in deployment config",
            pool.pool_contract_id
        )
    })?;
    let derived = BabyJubJubPoint::from_priv_scalar(d_priv)
        .ok_or_else(|| anyhow!("invalid GVK authority private key"))?;
    if &derived != configured {
        return Err(anyhow!(
            "GVK private key does not match gvkAuthorityPubKey for pool {}",
            pool.pool_contract_id
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Small fixed offsets over test seeds cannot overflow.
    #![allow(clippy::arithmetic_side_effects)]

    use super::*;

    fn field(value: u64) -> Field {
        Field(crate::types::U256::from(value))
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

    fn pool_entry(key: Option<BabyJubJubPoint>) -> PoolConfigEntry {
        PoolConfigEntry {
            pool_contract_id: "CPOOL".to_string(),
            token_contract_id: "CTOKEN".to_string(),
            deployment_ledger: 1,
            enabled: true,
            asset: crate::types::AssetDescriptor::Native,
            policy_flags: PolicyFlags::EMPTY,
            gvk_mode: GvkMode::ViewOnly,
            gvk_authority_pub_key: key,
        }
    }

    #[test]
    fn validate_gvk_authority_key_accepts_matching_key() -> Result<()> {
        use crate::zk::encryption::generate_random_blinding;

        let d_priv = generate_random_blinding()?;
        let pub_key = BabyJubJubPoint::from_priv_scalar(&d_priv).expect("derive pubkey");
        validate_gvk_authority_key(&d_priv, &pool_entry(Some(pub_key)))?;
        Ok(())
    }

    #[test]
    fn validate_gvk_authority_key_rejects_mismatch() -> Result<()> {
        use crate::zk::encryption::generate_random_blinding;

        let d_priv = generate_random_blinding()?;
        let err = validate_gvk_authority_key(&d_priv, &pool_entry(Some(point(7, 11))))
            .expect_err("wrong key for configured pubkey");
        assert!(
            format!("{err:#}").contains("does not match gvkAuthorityPubKey"),
            "{err:#}"
        );
        Ok(())
    }

    #[test]
    fn validate_gvk_authority_key_requires_configured_pubkey() {
        let err = validate_gvk_authority_key(&field(1), &pool_entry(None))
            .expect_err("missing configured pubkey");
        assert!(
            format!("{err:#}").contains("no gvkAuthorityPubKey"),
            "{err:#}"
        );
    }
}

#[cfg(test)]
mod on_chain_mode_tests {
    use super::*;

    /// These values are a wire contract with `pool_gvk::gvk::{VIEW_ONLY,
    /// TRACEABLE}`. Changing either side alone silently misreads deployed
    /// pools, so pin the literals.
    #[test]
    fn on_chain_values_match_the_contract_constants() {
        assert_eq!(GvkMode::Off.on_chain_value(), None);
        assert_eq!(GvkMode::ViewOnly.on_chain_value(), Some(1));
        assert_eq!(GvkMode::Traceable.on_chain_value(), Some(2));
    }

    #[test]
    fn on_chain_value_round_trips() -> Result<()> {
        for mode in [GvkMode::Off, GvkMode::ViewOnly, GvkMode::Traceable] {
            assert_eq!(GvkMode::from_on_chain_value(mode.on_chain_value())?, mode);
        }
        Ok(())
    }

    #[test]
    fn unknown_on_chain_value_is_an_error_not_off() {
        assert!(GvkMode::from_on_chain_value(Some(0)).is_err());
        assert!(GvkMode::from_on_chain_value(Some(3)).is_err());
        assert!(GvkMode::from_on_chain_value(Some(u32::MAX)).is_err());
    }
}
