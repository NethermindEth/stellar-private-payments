//! Baby JubJub curve helpers for Global View Key encryption.
//!
//! Circomlib's twisted Edwards arithmetic, with results matching
//! `circuits/src/test/utils/babyjub.rs`. `ark-ed-on-bn254` uses a normalized
//! curve form incompatible with the in-circuit semantics.

#![allow(clippy::arithmetic_side_effects)]

use crate::{
    types::{BabyJubJubPoint, Field},
    zk::serialization::{field_to_scalar, scalar_to_field},
};
use ark_bn254::Fr as Scalar;
use ark_ff::{BigInteger, BitIteratorBE, Field as _, MontFp, One, PrimeField, Zero};
use core::str::FromStr;
use subtle::{Choice, ConditionallySelectable};

const CURVE_A: Scalar = MontFp!("168700");
const CURVE_D: Scalar = MontFp!("168696");

/// The circomlib Baby JubJub generator `BASE8` (prime-order subgroup).
const BASE8_X: &str =
    "5299619240641551281634865583518297030282874472190772894086521144482721001553";
const BASE8_Y: &str =
    "16950150798460657717958625567821834550301663161624707787222815936182638968203";

/// An affine Baby JubJub point in circomlib coordinates. The identity is
/// `(0, 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Scalar,
    pub y: Scalar,
}

/// The group identity `(0, 1)`.
pub fn identity() -> Point {
    Point {
        x: Scalar::zero(),
        y: Scalar::one(),
    }
}

/// The circomlib `BASE8` generator.
pub fn base8() -> Point {
    Point {
        x: Scalar::from_str(BASE8_X).expect("Invalid BASE8 x coordinate"),
        y: Scalar::from_str(BASE8_Y).expect("Invalid BASE8 y coordinate"),
    }
}

/// Build a point from field-element coordinates.
///
/// The point is not validated, mirroring the circuit's treatment of an
/// untrusted public `D`.
pub fn point_from_coords(x: Scalar, y: Scalar) -> Point {
    Point { x, y }
}

/// Return a point's coordinates.
pub fn point_to_coords(p: Point) -> (Scalar, Scalar) {
    (p.x, p.y)
}

/// Complete twisted Edwards addition, matching circomlib's `BabyAdd`.
///
/// Returns `None` only when a denominator is not invertible.
pub fn add(p: Point, q: Point) -> Option<Point> {
    let beta = p.x * q.y;
    let gamma = p.y * q.x;
    let delta = (p.y - CURVE_A * p.x) * (q.x + q.y);
    let tau = beta * gamma;

    let x_den = (Scalar::one() + CURVE_D * tau).inverse()?;
    let y_den = (Scalar::one() - CURVE_D * tau).inverse()?;

    Some(Point {
        x: (beta + gamma) * x_den,
        y: (delta + CURVE_A * beta - gamma) * y_den,
    })
}

/// Point doubling, matching circomlib's `BabyDbl`.
pub fn double(p: Point) -> Option<Point> {
    add(p, p)
}

/// A projective point `(x : y : z)`, the affine point `(x/z, y/z)`.
#[derive(Clone, Copy)]
struct Projective {
    x: Scalar,
    y: Scalar,
    z: Scalar,
}

impl Projective {
    fn from_affine(p: Point) -> Self {
        Self {
            x: p.x,
            y: p.y,
            z: Scalar::one(),
        }
    }

    /// Unified addition add-2008-bbjlp, complete on the curve because `a` is a
    /// square in `Fr` and `d` is not.
    fn add(self, q: Self) -> Self {
        let a = self.z * q.z;
        let b = a.square();
        let c = self.x * q.x;
        let d = self.y * q.y;
        let e = CURVE_D * c * d;
        let f = b - e;
        let g = b + e;
        Self {
            x: a * f * ((self.x + self.y) * (q.x + q.y) - c - d),
            y: a * g * (d - CURVE_A * c),
            z: f * g,
        }
    }

    fn to_affine(self) -> Option<Point> {
        if self.z.is_zero() {
            return None;
        }
        // Fermat inversion; `inverse` is a GCD whose steps depend on `z`.
        let mut p_minus_2 = Scalar::MODULUS;
        p_minus_2.sub_with_borrow(&2u64.into());
        let z_inv = self.z.pow(p_minus_2);
        Some(Point {
            x: self.x * z_inv,
            y: self.y * z_inv,
        })
    }
}

fn conditional_swap(a: &mut Projective, b: &mut Projective, swap: Choice) {
    for (s, t) in [
        (&mut a.x, &mut b.x),
        (&mut a.y, &mut b.y),
        (&mut a.z, &mut b.z),
    ] {
        // The limbs are `#[doc(hidden)]` in ark-ff: no semver guarantee.
        for (u, v) in s.0.0.iter_mut().zip(&mut t.0.0) {
            u64::conditional_swap(u, v, swap);
        }
    }
}

/// Multiplies `point` by the integer value of `scalar` with a Montgomery
/// ladder.
///
/// Every bit costs one projective addition and one doubling, with a `subtle`
/// swap choosing the operands, so neither the steps nor the memory accesses
/// depend on the scalar's bits. Field arithmetic in ark-ff still branches on
/// operand values.
///
/// Returns `None` when the result has no affine form, which only a point off
/// the curve can produce.
pub fn scalar_mul(point: Point, scalar: Scalar) -> Option<Point> {
    let mut r0 = Projective::from_affine(identity());
    let mut r1 = Projective::from_affine(point);
    for bit in BitIteratorBE::new(scalar.into_bigint()) {
        let swap = Choice::from(u8::from(bit));
        conditional_swap(&mut r0, &mut r1, swap);
        r1 = r0.add(r1);
        r0 = r0.add(r0);
        conditional_swap(&mut r0, &mut r1, swap);
    }
    r0.to_affine()
}

/// Clear the cofactor: return `8 * point` (three doublings).
pub fn mul8(point: Point) -> Option<Point> {
    double(double(double(point)?)?)
}

impl Point {
    /// Whether this point satisfies the Baby JubJub curve equation.
    pub fn is_on_curve(self) -> bool {
        let x2 = self.x * self.x;
        let y2 = self.y * self.y;
        CURVE_A * x2 + y2 == Scalar::one() + CURVE_D * x2 * y2
    }
}

impl BabyJubJubPoint {
    /// Returns `scalar * BASE8`.
    pub fn from_priv_scalar(scalar: &Field) -> Option<Self> {
        Some(Self::from_point(scalar_mul(
            base8(),
            field_to_scalar(scalar),
        )?))
    }

    pub(crate) fn to_coords(&self) -> (Scalar, Scalar) {
        (field_to_scalar(&self.x), field_to_scalar(&self.y))
    }

    pub(crate) fn from_coords(x: Scalar, y: Scalar) -> Self {
        Self {
            x: scalar_to_field(&x),
            y: scalar_to_field(&y),
        }
    }

    fn from_point(p: Point) -> Self {
        let (x, y) = point_to_coords(p);
        Self::from_coords(x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prime order of the Baby JubJub subgroup generated by `BASE8`.
    const SUBGROUP_ORDER: &str =
        "2736030358979909402780800718157159386076813972158567259200215660948447373041";

    #[test]
    fn base8_is_on_curve() {
        assert!(base8().is_on_curve());
    }

    #[test]
    fn base8_has_prime_order() {
        let l = Scalar::from_str(SUBGROUP_ORDER).expect("valid subgroup order");
        assert_eq!(scalar_mul(base8(), l), Some(identity()));
    }

    #[test]
    fn mul8_matches_three_doublings() {
        let g = base8();
        assert_eq!(mul8(g), scalar_mul(g, Scalar::from(8u64)));
    }

    /// Variable-time double-and-add, the reference for `scalar_mul`.
    fn double_and_add(point: Point, scalar: Scalar) -> Option<Point> {
        let mut acc = identity();
        let mut base = point;
        for bit in scalar.into_bigint().to_bits_le() {
            if bit {
                acc = add(acc, base)?;
            }
            base = double(base)?;
        }
        Some(acc)
    }

    /// The ladder agrees with double-and-add on the identity, torsion points,
    /// and scalars at and above the subgroup order.
    #[test]
    fn scalar_mul_matches_double_and_add() {
        let g = base8();
        let l = Scalar::from_str(SUBGROUP_ORDER).expect("valid subgroup order");
        let inv_sqrt_a = CURVE_A
            .sqrt()
            .and_then(|s| s.inverse())
            .expect("a is a nonzero square");
        let torsion = [
            point_from_coords(Scalar::zero(), -Scalar::one()),
            point_from_coords(inv_sqrt_a, Scalar::zero()),
            point_from_coords(-inv_sqrt_a, Scalar::zero()),
        ];
        let points = [identity(), g, mul8(g).expect("valid mul8")]
            .into_iter()
            .chain(torsion)
            .chain(torsion.map(|t| add(g, t).expect("valid addition")));
        let scalars = [
            Scalar::zero(),
            Scalar::one(),
            Scalar::from(2u64),
            Scalar::from(8u64),
            l - Scalar::one(),
            l,
            l + Scalar::one(),
            -Scalar::one(),
            Scalar::from_str(
                "12345678901234567890123456789012345678901234567890123456789012345678901234567",
            )
            .expect("valid scalar"),
        ];
        for p in points {
            for k in scalars {
                assert_eq!(scalar_mul(p, k), double_and_add(p, k), "{p:?} * {k}");
            }
        }
    }

    #[test]
    fn scalar_mul_is_homomorphic() {
        let g = base8();
        let a = Scalar::from(123456u64);
        let b = Scalar::from(654321u64);
        assert_eq!(
            scalar_mul(g, a + b),
            add(
                scalar_mul(g, a).expect("valid scalar mul"),
                scalar_mul(g, b).expect("valid scalar mul")
            )
        );
    }
}
