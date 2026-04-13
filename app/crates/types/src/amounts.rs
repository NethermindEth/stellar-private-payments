//! Amount and field element types used across the app.
//!
//! These wrappers exist to:
//! - make signed vs unsigned intent explicit (`ExtAmount` vs `NoteAmount`)
//! - provide a single place for conversions into the circuit field (`Field`)
//! - support serde and (optionally) rusqlite storage conversions

use core::{
    fmt,
    ops::{Add, AddAssign, Neg, Sub, SubAssign},
    str::FromStr,
};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uint::construct_uint;

construct_uint! {
    /// Unsigned 256-bit integer used as the backing type for [`Field`].
    pub struct U256(4);
}

/// The BN254 scalar field modulus, as big-endian bytes.
///
/// This value is used to map signed `ext_amount` values into a field element for the circuit:
/// `FE(x) = x` if `x >= 0`, otherwise `FE(x) = p - |x|`.
///
/// Source: matches `BN256_MOD_BYTES` in `prover::crypto`.
pub const BN254_MODULUS_BE: [u8; 32] = [
    48, 100, 78, 114, 225, 49, 160, 41, 184, 80, 69, 182, 129, 129, 88, 93, 40, 51, 232, 72,
    121, 185, 112, 145, 67, 225, 245, 147, 240, 0, 0, 1,
];

fn bn254_modulus_u256() -> U256 {
    U256::from_big_endian(&BN254_MODULUS_BE)
}

/// Amount that appears inside encrypted notes.
///
/// This is always non-negative and is currently constrained to what fits in the encrypted
/// note plaintext format (u64, stored as 8 little-endian bytes).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NoteAmount(pub u64);

impl NoteAmount {
    /// Zero amount.
    pub const ZERO: NoteAmount = NoteAmount(0);
    /// Unit amount.
    pub const ONE: NoteAmount = NoteAmount(1);
    /// Maximum representable note amount (stored as `u64` stroops internally).
    pub const MAX: NoteAmount = NoteAmount(u64::MAX);

    /// Returns the underlying stroops value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns true if this amount is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns this amount as 8 little-endian bytes (stroops).
    ///
    /// This matches the current note encryption plaintext format:
    /// `amount (8 bytes LE) || blinding (32 bytes)`.
    pub const fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(NoteAmount)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(NoteAmount)
    }
}

impl fmt::Display for NoteAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for NoteAmount {
    fn from(value: u64) -> Self {
        NoteAmount(value)
    }
}

impl From<NoteAmount> for u64 {
    fn from(value: NoteAmount) -> Self {
        value.0
    }
}

impl FromStr for NoteAmount {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(NoteAmount(s.parse::<u64>().map_err(|e| anyhow!(e))?))
    }
}

impl TryFrom<ExtAmount> for NoteAmount {
    type Error = anyhow::Error;

    fn try_from(value: ExtAmount) -> Result<Self> {
        let v = u64::try_from(value.0)
            .map_err(|_| anyhow!("NoteAmount out of range: {}", value.0))?;
        Ok(NoteAmount(v))
    }
}

impl Add for NoteAmount {
    type Output = NoteAmount;

    fn add(self, rhs: Self) -> Self::Output {
        match self.checked_add(rhs) {
            Some(v) => v,
            None => panic!("NoteAmount overflow"),
        }
    }
}

impl AddAssign for NoteAmount {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for NoteAmount {
    type Output = NoteAmount;

    fn sub(self, rhs: Self) -> Self::Output {
        match self.checked_sub(rhs) {
            Some(v) => v,
            None => panic!("NoteAmount underflow"),
        }
    }
}

impl SubAssign for NoteAmount {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Serialize for NoteAmount {
    /// Serialize as a decimal string to preserve precision across JS/JSON.
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for NoteAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let v = s.parse::<u64>().map_err(serde::de::Error::custom)?;
        Ok(NoteAmount(v))
    }
}

/// Signed external/public amount
///
/// Soroban token transfer function allows only i128 amount
/// - Deposit: `ext_amount > 0`
/// - Withdraw: `ext_amount < 0`
/// - Transfer: `ext_amount = 0`
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ExtAmount(pub i128);

impl ExtAmount {
    /// Zero amount.
    pub const ZERO: ExtAmount = ExtAmount(0);
    /// Unit amount.
    pub const ONE: ExtAmount = ExtAmount(1);

    /// Returns the underlying signed stroops value.
    pub const fn as_i128(self) -> i128 {
        self.0
    }

    /// Returns true if this amount is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Checked addition.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(ExtAmount)
    }

    /// Checked subtraction.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(ExtAmount)
    }
}

impl fmt::Display for ExtAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<i128> for ExtAmount {
    fn from(value: i128) -> Self {
        ExtAmount(value)
    }
}

impl From<NoteAmount> for ExtAmount {
    fn from(value: NoteAmount) -> Self {
        ExtAmount(i128::from(value.0))
    }
}

impl From<ExtAmount> for i128 {
    fn from(value: ExtAmount) -> Self {
        value.0
    }
}

impl FromStr for ExtAmount {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(ExtAmount(s.parse::<i128>().map_err(|e| anyhow!(e))?))
    }
}

impl Add for ExtAmount {
    type Output = ExtAmount;

    fn add(self, rhs: Self) -> Self::Output {
        match self.checked_add(rhs) {
            Some(v) => v,
            None => panic!("ExtAmount overflow"),
        }
    }
}

impl AddAssign for ExtAmount {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for ExtAmount {
    type Output = ExtAmount;

    fn sub(self, rhs: Self) -> Self::Output {
        match self.checked_sub(rhs) {
            Some(v) => v,
            None => panic!("ExtAmount underflow"),
        }
    }
}

impl SubAssign for ExtAmount {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for ExtAmount {
    type Output = ExtAmount;

    fn neg(self) -> Self::Output {
        ExtAmount(-self.0)
    }
}

impl Serialize for ExtAmount {
    /// Serialize as a decimal string to preserve precision across JS/JSON.
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for ExtAmount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let v = s.parse::<i128>().map_err(serde::de::Error::custom)?;
        Ok(ExtAmount(v))
    }
}

/// BN254 scalar field element backed by a 256-bit unsigned integer.
///
/// This is primarily used for "public input" style values where the circuit expects
/// a field element, but the application wants to handle signed values (`ExtAmount`)
/// and map them into the field (see `TryFrom<ExtAmount> for Field`).
/// It is a lightweight app wrapper (to avoid pulling and locking into specific implementations
/// from ark crates etc.)
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Field(pub U256);

impl Field {
    /// The additive identity in the field.
    pub const ZERO: Field = Field(U256([0, 0, 0, 0]));
    /// The multiplicative identity in the field.
    pub const ONE: Field = Field(U256([1, 0, 0, 0]));

    /// Returns the field modulus `p` as a [`U256`].
    pub fn modulus() -> U256 {
        bn254_modulus_u256()
    }

    /// Returns true if this field element is zero.
    pub fn is_zero(self) -> bool {
        self == Field::ZERO
    }

    /// Returns the underlying integer representation.
    pub const fn as_u256(self) -> U256 {
        self.0
    }

    /// Converts this field element to 32-byte big-endian representation.
    pub fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.to_big_endian(&mut out);
        out
    }

    /// Converts this field element to 32-byte little-endian representation.
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.to_little_endian(&mut out);
        out
    }

    /// Builds a field element from a 32-byte big-endian representation.
    ///
    /// Fails if the value is not `< p`.
    pub fn try_from_be_bytes(bytes: [u8; 32]) -> Result<Self> {
        let v = U256::from_big_endian(&bytes);
        Field::try_from_u256(v)
    }

    /// Builds a field element from a 32-byte little-endian representation.
    ///
    /// Fails if the value is not `< p`.
    pub fn try_from_le_bytes(bytes: [u8; 32]) -> Result<Self> {
        let v = U256::from_little_endian(&bytes);
        Field::try_from_u256(v)
    }

    /// Builds a field element from a `U256`.
    ///
    /// Fails if the value is not `< p`.
    pub fn try_from_u256(v: U256) -> Result<Self> {
        let m = Self::modulus();
        if v >= m {
            return Err(anyhow!("field element out of range"));
        }
        Ok(Field(v))
    }

    /// Parses a `0x`-prefixed 64-hex string into a [`Field`] (big-endian).
    pub fn from_0x_hex_be(s: &str) -> Result<Self> {
        let be = parse_0x_hex_32(s)?;
        Field::try_from_be_bytes(be)
    }

    /// Returns this field element as a `0x`-prefixed 64-hex string (big-endian).
    pub fn to_0x_hex_be(self) -> String {
        let be = self.to_be_bytes();
        encode_0x_hex(&be)
    }
}

impl From<Field> for U256 {
    fn from(value: Field) -> Self {
        value.0
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_0x_hex_be())
    }
}

impl FromStr for Field {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Field::from_0x_hex_be(s)
    }
}

impl Serialize for Field {
    /// Serialize as a `0x`-prefixed 64-hex big-endian string.
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_0x_hex_be())
    }
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Field::from_0x_hex_be(&s).map_err(serde::de::Error::custom)
    }
}

impl From<NoteAmount> for Field {
    fn from(value: NoteAmount) -> Self {
        // `u64` is always < BN254 modulus.
        Field(U256::from(value.0))
    }
}

impl TryFrom<ExtAmount> for Field {
    type Error = anyhow::Error;

    fn try_from(value: ExtAmount) -> Result<Self> {
        let m = Field::modulus();
        if value.0 >= 0 {
            let v = U256::from(u128::try_from(value.0).map_err(|_| anyhow!("ext amount out of range"))?);
            // For i128, v is always < modulus in practice; keep a guard for completeness.
            if v >= m {
                return Err(anyhow!("ext amount out of field range"));
            }
            return Ok(Field(v));
        }

        // Negative mapping: FE(x) = p - |x|
        let abs: u128 = value.0.unsigned_abs();
        let abs_u256 = U256::from(abs);
        if abs_u256 >= m {
            return Err(anyhow!("ext amount abs out of field range"));
        }
        Ok(Field(m - abs_u256))
    }
}

impl Add for Field {
    type Output = Field;

    fn add(self, rhs: Self) -> Self::Output {
        let m = Field::modulus();
        let mut v = self.0 + rhs.0;
        if v >= m {
            v -= m;
        }
        Field(v)
    }
}

impl AddAssign for Field {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Field {
    type Output = Field;

    fn sub(self, rhs: Self) -> Self::Output {
        let m = Field::modulus();
        if self.0 >= rhs.0 {
            Field(self.0 - rhs.0)
        } else {
            Field(m - (rhs.0 - self.0))
        }
    }
}

impl SubAssign for Field {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

fn encode_0x_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + 64);
    out.push_str("0x");
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn parse_0x_hex_32(s: &str) -> Result<[u8; 32]> {
    let s = s.strip_prefix("0x").ok_or_else(|| anyhow!("expected 0x-prefixed hex"))?;
    if s.len() != 64 {
        return Err(anyhow!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for i in 0..32 {
        let hi = from_hex_nibble(bytes[i * 2])?;
        let lo = from_hex_nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn from_hex_nibble(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + (b - b'a')),
        b'A'..=b'F' => Ok(10 + (b - b'A')),
        _ => Err(anyhow!("invalid hex character")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn note_amount_serde_roundtrip() -> Result<()> {
        let a = NoteAmount(123);
        let s = serde_json::to_string(&a)?;
        assert_eq!(s, "\"123\"");

        let b: NoteAmount = serde_json::from_str(&s)?;
        assert_eq!(a, b);

        // Accept numeric JSON too.
        let c: NoteAmount = serde_json::from_str("\"456\"")?;
        assert_eq!(c, NoteAmount(456));
        Ok(())
    }

    #[test]
    fn ext_amount_serde_roundtrip() -> Result<()> {
        let a = ExtAmount(-7);
        let s = serde_json::to_string(&a)?;
        assert_eq!(s, "\"-7\"");

        let b: ExtAmount = serde_json::from_str(&s)?;
        assert_eq!(a, b);

        // Accept numeric JSON too.
        let c: ExtAmount = serde_json::from_str("\"-9\"")?;
        assert_eq!(c, ExtAmount(-9));
        Ok(())
    }

    #[test]
    fn note_amount_zero_min_max() -> Result<()> {
        let z = NoteAmount(0);
        assert_eq!(z.as_u64(), 0);
        assert_eq!(z.to_string(), "0");
        assert_eq!(z.to_le_bytes(), [0u8; 8]);

        let min = NoteAmount(u64::MIN);
        assert_eq!(min, z);

        let max = NoteAmount::MAX;

        // checked arithmetic corner cases
        assert_eq!(max.checked_add(NoteAmount(1)), None);
        assert_eq!(z.checked_sub(NoteAmount(1)), None);
        Ok(())
    }

    #[test]
    fn note_amount_try_from_ext_amount_range() -> Result<()> {
        assert_eq!(NoteAmount::try_from(ExtAmount(0))?, NoteAmount::ZERO);
        assert_eq!(
            NoteAmount::try_from(ExtAmount::from(NoteAmount::MAX))?,
            NoteAmount::MAX
        );

        assert!(NoteAmount::try_from(ExtAmount(-1)).is_err());

        let max_ext = ExtAmount::from(NoteAmount::MAX);
        let too_big = max_ext
            .checked_add(ExtAmount::ONE)
            .expect("i128 add");
        assert!(NoteAmount::try_from(too_big).is_err());
        Ok(())
    }

    #[test]
    fn ext_amount_zero_min_max() -> Result<()> {
        let z = ExtAmount(0);
        assert_eq!(z.as_i128(), 0);
        assert_eq!(z.to_string(), "0");

        let min = ExtAmount(i128::MIN);
        let max = ExtAmount(i128::MAX);
        assert_eq!(min.as_i128(), i128::MIN);
        assert_eq!(max.as_i128(), i128::MAX);

        // checked arithmetic corner cases
        assert_eq!(max.checked_add(ExtAmount(1)), None);
        assert_eq!(min.checked_sub(ExtAmount(1)), None);
        Ok(())
    }

    #[test]
    fn field_hex_roundtrip_and_range_check() -> Result<()> {
        let f = Field::try_from(ExtAmount(5))?;
        let s = f.to_0x_hex_be();
        let parsed = Field::from_0x_hex_be(&s)?;
        assert_eq!(f, parsed);

        // Zero is valid.
        let zero_hex = "0x0000000000000000000000000000000000000000000000000000000000000000";
        let z = Field::from_0x_hex_be(zero_hex)?;
        assert_eq!(z, Field(U256::from(0u64)));

        // p-1 is valid.
        let p = Field::modulus();
        let pm1 = Field(p - U256::from(1u64));
        let pm1_roundtrip = Field::from_0x_hex_be(&pm1.to_0x_hex_be())?;
        assert_eq!(pm1_roundtrip, pm1);

        // Modulus itself is out of range (field elements must be < p).
        let mod_hex = encode_0x_hex(&BN254_MODULUS_BE);
        assert!(Field::from_0x_hex_be(&mod_hex).is_err());
        Ok(())
    }

    #[test]
    fn field_try_from_ext_amount_negative_mapping_matches_js() -> Result<()> {
        // JS toFieldElement(-1) => p - 1
        let one = U256::from(1u64);
        let p = Field::modulus();

        let fe_neg1 = Field::try_from(ExtAmount(-1))?;
        assert_eq!(U256::from(fe_neg1), p - one);

        let fe_zero = Field::try_from(ExtAmount(0))?;
        assert_eq!(U256::from(fe_zero), U256::from(0u64));
        Ok(())
    }

    #[test]
    fn field_add_sub_are_modular() -> Result<()> {
        let p = Field::modulus();
        let one = Field(U256::from(1u64));
        let pm1 = Field(p - U256::from(1u64));

        assert_eq!(pm1 + one, Field(U256::from(0u64)));
        assert_eq!(Field(U256::from(0u64)) - one, pm1);
        Ok(())
    }

    #[test]
    fn try_from_amounts_to_field_corners() -> Result<()> {
        // NoteAmount always maps directly.
        let n0 = Field::try_from(NoteAmount(0))?;
        assert_eq!(U256::from(n0), U256::from(0u64));
        let nmax = Field::try_from(NoteAmount(u64::MAX))?;
        assert_eq!(U256::from(nmax), U256::from(u64::MAX));

        // ExtAmount maps signed values into the field.
        let p = Field::modulus();
        let e0 = Field::try_from(ExtAmount(0))?;
        assert_eq!(U256::from(e0), U256::from(0u64));

        let epos = Field::try_from(ExtAmount(123))?;
        assert_eq!(U256::from(epos), U256::from(123u64));

        let eneg = Field::try_from(ExtAmount(-123))?;
        assert_eq!(U256::from(eneg), p - U256::from(123u64));

        // i128::MIN maps to p - 2^127.
        let emin = Field::try_from(ExtAmount(i128::MIN))?;
        let abs = U256::from(1u128 << 127);
        assert_eq!(U256::from(emin), p - abs);
        Ok(())
    }

    #[test]
    fn field_try_from_le_bytes_roundtrip() -> Result<()> {
        let f = Field::try_from(ExtAmount(-123))?;
        let le = f.to_le_bytes();
        let parsed = Field::try_from_le_bytes(le)?;
        assert_eq!(parsed, f);
        Ok(())
    }

    #[cfg(feature = "rusqlite")]
    #[test]
    fn rusqlite_conversions_work() -> Result<()> {
        use rusqlite::types::{FromSql, ToSql, Value, ValueRef};

        // NoteAmount as INTEGER.
        let n = NoteAmount(42);
        let out = n.to_sql()?;
        match out {
            rusqlite::types::ToSqlOutput::Owned(Value::Integer(i)) => {
                let parsed = NoteAmount::column_result(ValueRef::Integer(i))?;
                assert_eq!(parsed, n);
            }
            _ => return Err(anyhow!("unexpected ToSql output for NoteAmount")),
        }

        // NoteAmount i64 boundary.
        let n_i64_max = NoteAmount(i64::MAX as u64);
        let out = n_i64_max.to_sql()?;
        match out {
            rusqlite::types::ToSqlOutput::Owned(Value::Integer(i)) => {
                assert_eq!(i, i64::MAX);
            }
            _ => return Err(anyhow!("unexpected ToSql output for NoteAmount(i64::MAX)")),
        }
        let n_over = NoteAmount((i64::MAX as u64) + 1);
        assert!(n_over.to_sql().is_err());

        // Field as BLOB(32).
        let f = Field::try_from(ExtAmount(-1))?;
        let out = f.to_sql()?;
        match out {
            rusqlite::types::ToSqlOutput::Owned(Value::Blob(b)) => {
                assert_eq!(b.len(), 32);
                let parsed = Field::column_result(ValueRef::Blob(&b))?;
                assert_eq!(parsed, f);
            }
            _ => return Err(anyhow!("unexpected ToSql output for Field")),
        }

        Ok(())
    }
}

    #[cfg(feature = "rusqlite")]
    mod rusqlite_impls {
    //! Rusqlite conversions for amount and field types.
    //!
    //! These are feature-gated to avoid pulling rusqlite into WASM builds.

    use super::{ExtAmount, Field, NoteAmount};
    use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, Value, ValueRef};

    impl ToSql for NoteAmount {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            // SQLite INTEGER is signed i64; note amounts are expected to fit within i64 for XLM stroops.
            let v: i64 = i64::try_from(self.0)
                .map_err(|_| rusqlite::Error::ToSqlConversionFailure(Box::new(FromSqlError::OutOfRange(0))))?;
            Ok(ToSqlOutput::Owned(Value::Integer(v)))
        }
    }

    impl FromSql for NoteAmount {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            match value {
                ValueRef::Integer(i) => {
                    if i < 0 {
                        return Err(FromSqlError::OutOfRange(i));
                    }
                    Ok(NoteAmount(i as u64))
                }
                _ => Err(FromSqlError::InvalidType),
            }
        }
    }

    impl ToSql for ExtAmount {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            // For current usage (stroops), ext amounts should fit in i64.
            let v: i64 = i64::try_from(self.0).map_err(|_| rusqlite::Error::ToSqlConversionFailure(Box::new(FromSqlError::OutOfRange(0))))?;
            Ok(ToSqlOutput::Owned(Value::Integer(v)))
        }
    }

    impl FromSql for ExtAmount {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            match value {
                ValueRef::Integer(i) => Ok(ExtAmount(i128::from(i))),
                _ => Err(FromSqlError::InvalidType),
            }
        }
    }

    impl ToSql for Field {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            // Store as 32-byte little-endian blob (matches prover/circuit byte order).
            Ok(ToSqlOutput::Owned(Value::Blob(self.to_le_bytes().to_vec())))
        }
    }

    impl FromSql for Field {
        fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
            match value {
                ValueRef::Blob(b) => {
                    if b.len() != 32 {
                        return Err(FromSqlError::InvalidBlobSize { expected_size: 32, blob_size: b.len() });
                    }
                    let mut le = [0u8; 32];
                    le.copy_from_slice(b);
                    Field::try_from_le_bytes(le).map_err(|_| FromSqlError::OutOfRange(0))
                }
                ValueRef::Text(t) => {
                    let s = core::str::from_utf8(t).map_err(|_| FromSqlError::InvalidType)?;
                    Field::from_0x_hex_be(s).map_err(|_| FromSqlError::InvalidType)
                }
                _ => Err(FromSqlError::InvalidType),
            }
        }
    }
}
