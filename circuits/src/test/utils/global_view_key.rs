//! Rust reference implementation of the Global View Key (GVK) encryption
//! scheme, mirroring `circuits/src/globalViewKey.circom`.
//!
//! Used by the circuit tests to compute known-answer values and to check the
//! admin-side decryption round-trip.
//!
//! Domain-separation tags
//!   0x05 - ephemeral scalar `r` derivation
//!   0x06 - keystream KDF

// Finite-field arithmetic cannot overflow. Adding here because of clippy warnings
#![allow(clippy::arithmetic_side_effects)]

use zkhash::{
    fields::bn256::FpBN256 as Scalar,
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS_4},
};

use super::{
    babyjub::{Point, base8, mul8, point_from_coords, point_to_coords, scalar_mul},
    general::poseidon2_hash3,
};

/// Domain separation for the `r` derivation chain.
const DOM_R: u64 = 0x05;
/// Domain separation for the keystream KDF.
const DOM_KDF: u64 = 0x06;

/// A note's plaintext secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub pk: Scalar,
    pub amount: Scalar,
    pub blinding: Scalar,
}

/// The ciphertext produced for a single note: ephemeral key `R` and the three
/// masked field elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub r: (Scalar, Scalar),        // It should be uppercase, as it's an EC point
    pub c1: Scalar,
    pub c2: Scalar,
    pub c3: Scalar,
}

/// Derive the ephemeral scalar `r` via the chained Poseidon2 absorb (dom 0x05).
///
/// `r = H(H(H(pk, amount, blinding), D.x, D.y), nonce, idx)`.
pub fn derive_r(note: &Note, d: (Scalar, Scalar), nonce: Scalar, idx: Scalar) -> Scalar {
    let dom = Some(Scalar::from(DOM_R));
    let h1 = poseidon2_hash3(note.pk, note.amount, note.blinding, dom);
    let h2 = poseidon2_hash3(h1, d.0, d.1, dom);
    poseidon2_hash3(h2, nonce, idx, dom)
}

/// The ephemeral public key `R = r * BASE8`.
pub fn ephemeral_r(r: Scalar) -> Point {
    scalar_mul(base8(), r)
}

/// The shared secret `S = r * (8 * D)`, matching the circuit's cofactor-cleared
/// ECDH. `D` is provided as untrusted coordinates.
pub fn shared_secret(r: Scalar, d: (Scalar, Scalar)) -> Point {
    scalar_mul(mul8(point_from_coords(d.0, d.1)), r)
}

/// The three keystream pads from a single width-4 Poseidon2 permutation over
/// `(S.x, S.y, 0, 0x06)`. Only the first three lanes are used; the fourth is the
/// capacity and never exposed.
pub fn keystream(s: Point) -> [Scalar; 3] {
    let (sx, sy) = point_to_coords(s);
    let h = Poseidon2::new(&POSEIDON2_BN256_PARAMS_4);
    let perm = h.permutation(&[sx, sy, Scalar::from(0u64), Scalar::from(DOM_KDF)]);
    [perm[0], perm[1], perm[2]]
}

/// Encrypt a note under authority key `D`, nonce and per-note index, exactly as
/// the circuit does.
pub fn encrypt_note(note: &Note, d: (Scalar, Scalar), nonce: Scalar, idx: Scalar) -> Ciphertext {
    let r = derive_r(note, d, nonce, idx);
    let big_r = point_to_coords(ephemeral_r(r));
    let k = keystream(shared_secret(r, d));
    Ciphertext {
        r: big_r,
        c1: note.pk + k[0],
        c2: note.amount + k[1],
        c3: note.blinding + k[2],
    }
}

/// Admin-side decryption using the authority private scalar `d`.
///
/// The circuit computes `S = r * (8*D)`, so with `D = d * BASE8` the admin must
/// recover `S = 8d * R`. We compute it as `8 * (d * R)` to keep `d` in range.
pub fn decrypt_note(ct: &Ciphertext, d_priv: Scalar) -> Note {
    let big_r = point_from_coords(ct.r.0, ct.r.1);
    let s = mul8(scalar_mul(big_r, d_priv));
    let k = keystream(s);
    Note {
        pk: ct.c1 - k[0],
        amount: ct.c2 - k[1],
        blinding: ct.c3 - k[2],
    }
}

/// The authority public key `D = d * BASE8` for a private scalar `d`.
pub fn admin_public_key(d_priv: Scalar) -> (Scalar, Scalar) {
    point_to_coords(scalar_mul(base8(), d_priv))
}
