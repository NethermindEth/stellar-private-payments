//! Global View Key (GVK) encryption and decryption.
//!
//! Off-chain port of `circuits/src/test/utils/global_view_key.rs`, wired to SDK
//! types in `crate::types::gvk`.
//!
//! Domain-separation tags:
//! - `0x05` — ephemeral scalar `r` derivation
//! - `0x06` — keystream KDF

#![allow(clippy::arithmetic_side_effects)]

use crate::{
    types::{
        BabyJubJubPoint, Field, GlobalViewKeyCiphertext, GlobalViewKeyMemo, GlobalViewKeyMode,
        GvkMode, NoteAmount,
    },
    zk::{
        babyjub::{self, Point},
        crypto::{self, poseidon2_hash3_internal},
        encryption::generate_random_blinding,
        serialization::{field_to_scalar, scalar_to_field},
    },
};
use anyhow::{Result, anyhow, bail};
use ark_bn254::Fr as Scalar;
use std::collections::HashSet;
use taceo_poseidon2::bn254::t4;

/// Domain separation for the `r` derivation chain.
const DOM_R: u64 = 0x05;
/// Domain separation for the keystream KDF.
const DOM_KDF: u64 = 0x06;

/// Plaintext note secrets encrypted under the admin view key.
///
/// `salt` seeds the ephemeral scalar derivation and is never transmitted or
/// recoverable by decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GvkNote {
    pub pk: Field,
    pub amount: Field,
    pub blinding: Field,
    pub salt: Field,
}

/// The subset of note secrets an admin recovers by decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GvkRecoveredNote {
    pub pk: Field,
    pub amount: Field,
    pub blinding: Field,
}

impl GvkNote {
    pub fn new(pk: Field, amount: NoteAmount, blinding: Field, salt: Field) -> Self {
        Self {
            pk,
            amount: Field::from(amount),
            blinding,
            salt,
        }
    }

    /// Encrypt this note under authority key `D`, nonce, and per-note index.
    pub fn encrypt(
        &self,
        admin_pub_key: &BabyJubJubPoint,
        nonce: &Field,
        idx: usize,
    ) -> Result<GlobalViewKeyCiphertext> {
        let d = admin_pub_key.to_coords();
        let nonce = field_to_scalar(nonce);
        let idx = u64::try_from(idx)
            .map(Scalar::from)
            .map_err(|_| anyhow!("note encryption index {idx} exceeds u64"))?;
        let r = self.derive_r(d, nonce, idx);
        let big_r = babyjub::point_to_coords(babyjub::scalar_mul(babyjub::base8(), r));
        let k = keystream(shared_secret(r, d));
        Ok(GlobalViewKeyCiphertext {
            r: BabyJubJubPoint::from_coords(big_r.0, big_r.1),
            c1: scalar_to_field(&(field_to_scalar(&self.pk) + k[0])),
            c2: scalar_to_field(&(field_to_scalar(&self.amount) + k[1])),
            c3: scalar_to_field(&(field_to_scalar(&self.blinding) + k[2])),
        })
    }

    fn derive_r(&self, d: (Scalar, Scalar), nonce: Scalar, idx: Scalar) -> Scalar {
        let dom = Some(Scalar::from(DOM_R));
        let pk = field_to_scalar(&self.pk);
        let amount = field_to_scalar(&self.amount);
        let blinding = field_to_scalar(&self.blinding);
        let salt = field_to_scalar(&self.salt);

        let h1 = poseidon2_hash3_internal(pk, amount, blinding, dom);
        let h2 = poseidon2_hash3_internal(h1, salt, d.0, dom);
        let h3 = poseidon2_hash3_internal(h2, d.1, nonce, dom);
        poseidon2_hash3_internal(h3, idx, Scalar::from(0u64), dom)
    }
}

/// Admin-recovered note secrets verified against an on-chain commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GvkAuditedNote {
    pub note: GvkRecoveredNote,
    pub commitment: Field,
}

impl GvkRecoveredNote {
    pub fn amount(&self) -> NoteAmount {
        let bytes = self.amount.to_le_bytes();
        let mut amount_le = [0u8; 16];
        amount_le.copy_from_slice(&bytes[..16]);
        NoteAmount::from(u128::from_le_bytes(amount_le))
    }
}

impl GlobalViewKeyCiphertext {
    /// Admin-side decryption using the authority private scalar `d`.
    pub fn decrypt(&self, d_priv: &Field) -> GvkRecoveredNote {
        let d_priv = field_to_scalar(d_priv);
        let big_r =
            babyjub::point_from_coords(field_to_scalar(&self.r.x), field_to_scalar(&self.r.y));
        let k = keystream(babyjub::mul8(babyjub::scalar_mul(big_r, d_priv)));
        GvkRecoveredNote {
            pk: scalar_to_field(&(field_to_scalar(&self.c1) - k[0])),
            amount: scalar_to_field(&(field_to_scalar(&self.c2) - k[1])),
            blinding: scalar_to_field(&(field_to_scalar(&self.c3) - k[2])),
        }
    }

    /// Decrypt and verify the recovered plaintext against
    /// `expected_commitment`.
    ///
    /// Returns `None` when decryption yields a dummy (zero-amount) note or the
    /// recomputed commitment does not match (wrong key, tampered ciphertext, or
    /// corrupt data).
    pub fn decrypt_audited_for_commitment(
        &self,
        d_priv: &Field,
        expected_commitment: &Field,
    ) -> Option<GvkAuditedNote> {
        audited_from_recovered(self.decrypt(d_priv), expected_commitment)
    }
}

/// Decrypt `ciphertext` and return the recovered note when its recomputed
/// commitment appears in `candidate_commitments`.
///
/// Used for traceable-mode nullifier events, which carry a spent-note
/// ciphertext but not the commitment itself.
pub fn try_decrypt_against_commitments(
    d_priv: &Field,
    ciphertext: &GlobalViewKeyCiphertext,
    candidate_commitments: impl IntoIterator<Item = Field>,
) -> Option<GvkAuditedNote> {
    let commitments: HashSet<Field> = candidate_commitments.into_iter().collect();
    try_decrypt_against_commitment_set(d_priv, ciphertext, &commitments)
}

/// Like [`try_decrypt_against_commitments`], but accepts a pre-built set so
/// pool-wide audits hash each recovered note once.
pub fn try_decrypt_against_commitment_set(
    d_priv: &Field,
    ciphertext: &GlobalViewKeyCiphertext,
    candidate_commitments: &HashSet<Field>,
) -> Option<GvkAuditedNote> {
    let recovered = ciphertext.decrypt(d_priv);
    audited_from_recovered_in_set(recovered, candidate_commitments)
}

pub(crate) fn commitment_field_for_recovered(recovered: &GvkRecoveredNote) -> Option<Field> {
    if recovered.amount().is_zero() {
        return None;
    }

    let computed = crypto::compute_commitment(
        &recovered.amount.to_le_bytes(),
        &recovered.pk.to_le_bytes(),
        &recovered.blinding.to_le_bytes(),
    )
    .ok()?;
    let computed_le: [u8; 32] = computed.as_slice().try_into().ok()?;
    Field::try_from_le_bytes(computed_le).ok()
}

fn audited_from_recovered(
    recovered: GvkRecoveredNote,
    expected_commitment: &Field,
) -> Option<GvkAuditedNote> {
    let computed = commitment_field_for_recovered(&recovered)?;
    if computed != *expected_commitment {
        return None;
    }

    Some(GvkAuditedNote {
        note: recovered,
        commitment: computed,
    })
}

fn audited_from_recovered_in_set(
    recovered: GvkRecoveredNote,
    candidate_commitments: &HashSet<Field>,
) -> Option<GvkAuditedNote> {
    let computed = commitment_field_for_recovered(&recovered)?;
    if !candidate_commitments.contains(&computed) {
        return None;
    }

    Some(GvkAuditedNote {
        note: recovered,
        commitment: computed,
    })
}

impl GlobalViewKeyMemo {
    /// Build a memo for a transaction's notes.
    ///
    /// `n_input_slots` is the circuit's input slot count (currently `2`), used
    /// to compute the per-note encryption index for outputs (`idx =
    /// n_input_slots + k`). Input `k` uses `idx = k` and is encrypted only in
    /// traceable mode.
    pub fn build(
        gvk_mode: GvkMode,
        admin_pub_key: BabyJubJubPoint,
        nonce: Field,
        input_notes: &[GvkNote],
        output_notes: &[GvkNote],
        n_input_slots: usize,
    ) -> Result<Self> {
        let mode = match gvk_mode {
            GvkMode::Off => bail!("cannot build a GlobalViewKeyMemo for GvkMode::Off"),
            GvkMode::ViewOnly => GlobalViewKeyMode::ViewOnly,
            GvkMode::Traceable => GlobalViewKeyMode::Traceable,
        };

        let outputs = output_notes
            .iter()
            .enumerate()
            .map(|(k, note)| {
                let idx = n_input_slots
                    .checked_add(k)
                    .ok_or_else(|| anyhow!("output encryption index overflow"))?;
                note.encrypt(&admin_pub_key, &nonce, idx)
            })
            .collect::<Result<Vec<_>>>()?;

        let inputs = if gvk_mode == GvkMode::Traceable {
            Some(
                input_notes
                    .iter()
                    .enumerate()
                    .map(|(k, note)| note.encrypt(&admin_pub_key, &nonce, k))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            None
        };

        let memo = Self {
            version: crate::types::GLOBAL_VIEW_KEY_MEMO_VERSION,
            mode,
            admin_pub_key,
            nonce,
            outputs,
            inputs,
        };
        memo.validate(input_notes.len(), output_notes.len())?;
        Ok(memo)
    }

    /// Decrypt every ciphertext in this memo.
    ///
    /// Returns `(input_notes, output_notes)`. Input notes are `None` in
    /// view-only mode.
    pub fn decrypt(
        &self,
        d_priv: &Field,
        n_inputs: usize,
        n_outputs: usize,
    ) -> Result<(Option<Vec<GvkRecoveredNote>>, Vec<GvkRecoveredNote>)> {
        self.validate(n_inputs, n_outputs)?;

        let outputs = self
            .outputs
            .iter()
            .map(|ct| ct.decrypt(d_priv))
            .collect::<Vec<_>>();

        let inputs = self.inputs.as_ref().map(|input_cts| {
            input_cts
                .iter()
                .map(|ct| ct.decrypt(d_priv))
                .collect::<Vec<_>>()
        });

        Ok((inputs, outputs))
    }
}

/// Generate a fresh per-note salt for GVK encryption.
pub fn generate_gvk_salt() -> Result<Field> {
    generate_random_blinding()
}

/// Generate a fresh per-transaction nonce for GVK encryption.
pub fn generate_gvk_nonce() -> Result<Field> {
    generate_random_blinding()
}

fn shared_secret(r: Scalar, d: (Scalar, Scalar)) -> Point {
    babyjub::scalar_mul(babyjub::mul8(babyjub::point_from_coords(d.0, d.1)), r)
}

fn keystream(s: Point) -> [Scalar; 3] {
    let (sx, sy) = babyjub::point_to_coords(s);
    let perm = t4::permutation(&[sx, sy, Scalar::from(0u64), Scalar::from(DOM_KDF)]);
    [perm[0], perm[1], perm[2]]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{types::GLOBAL_VIEW_KEY_MEMO_VERSION, zk::crypto};

    fn field(value: u64) -> Field {
        Field(crate::types::U256::from(value))
    }

    fn sample_note() -> GvkNote {
        GvkNote {
            pk: field(0xABCD),
            amount: field(1_000_000),
            blinding: field(0xDEAD_BEEF),
            salt: field(0xCAFE_F00D),
        }
    }

    #[test]
    fn decrypt_audited_for_commitment_rejects_wrong_commitment() -> Result<()> {
        let d_priv = field(7);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = sample_note();
        let ct = note.encrypt(&admin, &field(5), 0)?;
        assert!(
            ct.decrypt_audited_for_commitment(&d_priv, &field(0xBAD))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn decrypt_audited_for_commitment_accepts_valid_note() -> Result<()> {
        let d_priv = field(7);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = sample_note();
        let ct = note.encrypt(&admin, &field(5), 0)?;
        let commitment_le = crypto::compute_commitment(
            &note.amount.to_le_bytes(),
            &note.pk.to_le_bytes(),
            &note.blinding.to_le_bytes(),
        )?;
        let commitment = Field::try_from_le_bytes(
            commitment_le
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("commitment hash is not 32 bytes"))?,
        )?;
        let audited = ct
            .decrypt_audited_for_commitment(&d_priv, &commitment)
            .expect("valid audited note");
        assert_eq!(audited.note.pk, note.pk);
        assert_eq!(audited.note.amount(), NoteAmount::from(1_000_000u128));
        assert_eq!(audited.note.blinding, note.blinding);
        Ok(())
    }

    #[test]
    fn known_answer_roundtrip() -> Result<()> {
        let d_priv = field(987_654_321);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = sample_note();
        let ct = note.encrypt(&admin, &field(42), 0)?;
        let recovered = ct.decrypt(&d_priv);

        assert_eq!(recovered.pk, note.pk);
        assert_eq!(recovered.amount, note.amount);
        assert_eq!(recovered.blinding, note.blinding);
        Ok(())
    }

    #[test]
    fn keystream_no_reuse_across_idx() -> Result<()> {
        let d_priv = field(11);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let nonce = field(99);
        let note = sample_note();
        let ct0 = note.encrypt(&admin, &nonce, 0)?;
        let ct1 = note.encrypt(&admin, &nonce, 1)?;

        assert_ne!(ct0.r, ct1.r);
        assert_ne!(ct0.c1, ct1.c1);
        Ok(())
    }

    #[test]
    fn distinct_nonce_changes_ciphertext() -> Result<()> {
        let d_priv = field(11);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = sample_note();
        let a = note.encrypt(&admin, &field(1), 0)?;
        let b = note.encrypt(&admin, &field(2), 0)?;
        assert_ne!(a.r, b.r);
        assert_ne!(a.c1, b.c1);
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_not_recovered() -> Result<()> {
        let d_priv = field(7);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let note = sample_note();
        let mut ct = note.encrypt(&admin, &field(5), 0)?;
        ct.c1 = field(0x1234_5678);
        let recovered = ct.decrypt(&d_priv);
        assert_ne!(recovered.pk, note.pk);
        Ok(())
    }

    #[test]
    fn view_only_memo_roundtrip() -> Result<()> {
        let d_priv = field(0x5EED);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let nonce = field(0xFEED_FACE);

        let inputs = vec![
            GvkNote {
                pk: field(111),
                amount: field(50),
                blinding: field(11),
                salt: field(0xDEADBEEF),
            },
            GvkNote {
                pk: field(222),
                amount: field(30),
                blinding: field(22),
                salt: field(0xDEADBEE0),
            },
        ];
        let outputs = vec![
            GvkNote {
                pk: field(333),
                amount: field(60),
                blinding: field(33),
                salt: field(0xC0FFE0),
            },
            GvkNote {
                pk: field(444),
                amount: field(20),
                blinding: field(44),
                salt: field(0xC0FFE1),
            },
        ];

        let memo = GlobalViewKeyMemo::build(GvkMode::ViewOnly, admin, nonce, &inputs, &outputs, 2)?;

        assert_eq!(memo.version, GLOBAL_VIEW_KEY_MEMO_VERSION);
        assert_eq!(memo.mode, GlobalViewKeyMode::ViewOnly);
        assert!(memo.inputs.is_none());
        assert_eq!(memo.outputs.len(), 2);

        let (dec_inputs, dec_outputs) = memo.decrypt(&d_priv, 2, 2)?;
        assert!(dec_inputs.is_none());
        for (expected, got) in outputs.iter().zip(dec_outputs) {
            assert_eq!(got.pk, expected.pk);
            assert_eq!(got.amount, expected.amount);
            assert_eq!(got.blinding, expected.blinding);
        }
        Ok(())
    }

    #[test]
    fn traceable_memo_roundtrip() -> Result<()> {
        let d_priv = field(0x5EED);
        let admin = BabyJubJubPoint::from_priv_scalar(&d_priv);
        let nonce = field(0xFEED_FACE);

        let inputs = vec![GvkNote {
            pk: field(111),
            amount: field(50),
            blinding: field(11),
            salt: field(0xDEADBEEF),
        }];
        let outputs = vec![GvkNote {
            pk: field(333),
            amount: field(50),
            blinding: field(33),
            salt: field(0xC0FFE0),
        }];

        let memo =
            GlobalViewKeyMemo::build(GvkMode::Traceable, admin, nonce, &inputs, &outputs, 2)?;

        assert_eq!(memo.mode, GlobalViewKeyMode::Traceable);
        assert_eq!(memo.inputs.as_ref().expect("inputs").len(), 1);

        let (dec_inputs, dec_outputs) = memo.decrypt(&d_priv, 1, 1)?;
        let dec_inputs = dec_inputs.expect("inputs");
        assert_eq!(dec_inputs.len(), 1);
        assert_eq!(dec_inputs[0].pk, inputs[0].pk);
        assert_eq!(dec_outputs[0].pk, outputs[0].pk);
        Ok(())
    }
}
