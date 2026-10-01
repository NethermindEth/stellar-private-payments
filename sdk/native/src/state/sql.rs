//! Turso ⇄ domain-type conversions for the local storage layer.
//!
//! `turso::Row::get::<T>()` requires `T: turso_core::types::FromValue`, and
//! that trait is **sealed** (`pub trait FromValue: Sealed`), so the SDK's
//! domain types cannot implement it. Reads therefore go through
//! `Row::get_value()` plus the [`SqlValue`] conversions here.
//!
//! Writes go the other way: Turso's `params!` is blanket-implemented over
//! `T: TryInto<Value>`, so implementing `TryFrom<T> for Value` makes the domain
//! types usable directly as statement parameters.

use turso::{Error as SqlError, Value};

use crate::types::{
    EncryptionPrivateKey, EncryptionPublicKey, ExtAmount, Field, NoteAmount, NotePrivateKey,
    NotePublicKey,
};

/// Read column `idx` of `row` and convert it to `T`.
pub(crate) fn get<T: SqlValue>(row: &turso::Row, idx: usize) -> Result<T, SqlError> {
    T::from_value(row.get_value(idx)?)
}

fn type_error(expected: &str, got: &Value) -> SqlError {
    let kind = match got {
        Value::Null => "NULL",
        Value::Integer(_) => "INTEGER",
        Value::Real(_) => "REAL",
        Value::Text(_) => "TEXT",
        Value::Blob(_) => "BLOB",
    };
    SqlError::ConversionFailure(format!("expected {expected}, found {kind}"))
}

/// Conversion from a Turso SQL value into a Rust type.
///
/// This mirrors the semantics of the `FromSql` impls the storage layer used to
/// have, so the on-disk representation is unchanged.
pub(crate) trait SqlValue: Sized {
    fn from_value(value: Value) -> Result<Self, SqlError>;
}

impl<T: SqlValue> SqlValue for Option<T> {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Null => Ok(None),
            other => T::from_value(other).map(Some),
        }
    }
}

impl SqlValue for Value {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        Ok(value)
    }
}

impl SqlValue for i64 {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Integer(i) => Ok(i),
            other => Err(type_error("INTEGER", &other)),
        }
    }
}

impl SqlValue for i32 {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Integer(i) => i32::try_from(i)
                .map_err(|_| SqlError::ConversionFailure(format!("{i} out of range for i32"))),
            other => Err(type_error("INTEGER", &other)),
        }
    }
}

impl SqlValue for u32 {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Integer(i) => u32::try_from(i)
                .map_err(|_| SqlError::ConversionFailure(format!("{i} out of range for u32"))),
            other => Err(type_error("INTEGER", &other)),
        }
    }
}

impl SqlValue for u64 {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Integer(i) => u64::try_from(i)
                .map_err(|_| SqlError::ConversionFailure(format!("{i} out of range for u64"))),
            other => Err(type_error("INTEGER", &other)),
        }
    }
}

impl SqlValue for String {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Text(t) => Ok(t),
            other => Err(type_error("TEXT", &other)),
        }
    }
}

impl SqlValue for Vec<u8> {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Blob(b) => Ok(b),
            other => Err(type_error("BLOB", &other)),
        }
    }
}

/// `NoteAmount` is stored as its decimal TEXT representation.
impl SqlValue for NoteAmount {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Text(t) => t
                .parse::<NoteAmount>()
                .map_err(|_| SqlError::ConversionFailure("invalid NoteAmount text".to_string())),
            other => Err(type_error("TEXT", &other)),
        }
    }
}

/// `ExtAmount` is stored as INTEGER (stroops fit in i64 for current usage).
impl SqlValue for ExtAmount {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Integer(i) => Ok(ExtAmount::from(i128::from(i))),
            other => Err(type_error("INTEGER", &other)),
        }
    }
}

/// `Field` is stored as a 32-byte little-endian BLOB, or 0x-hex LE TEXT.
impl SqlValue for Field {
    fn from_value(value: Value) -> Result<Self, SqlError> {
        match value {
            Value::Blob(b) => {
                let le: [u8; 32] = b.try_into().map_err(|_| {
                    SqlError::ConversionFailure("Field blob must be exactly 32 bytes".to_string())
                })?;
                Field::try_from_le_bytes(le)
                    .map_err(|_| SqlError::ConversionFailure("invalid Field".to_string()))
            }
            Value::Text(t) => Field::from_0x_hex_le_bytes(&t)
                .map_err(|_| SqlError::ConversionFailure("invalid Field hex".to_string())),
            other => Err(type_error("BLOB or TEXT", &other)),
        }
    }
}

macro_rules! impl_blob32_key {
    ($ty:ident) => {
        impl SqlValue for $ty {
            fn from_value(value: Value) -> Result<Self, SqlError> {
                match value {
                    Value::Blob(b) => {
                        let out: [u8; 32] = b.try_into().map_err(|_| {
                            SqlError::ConversionFailure(format!(
                                "{} blob must be exactly 32 bytes",
                                stringify!($ty)
                            ))
                        })?;
                        Ok($ty(out))
                    }
                    other => Err(type_error("BLOB", &other)),
                }
            }
        }

        impl TryFrom<$ty> for Value {
            type Error = SqlError;

            fn try_from(value: $ty) -> Result<Self, SqlError> {
                Ok(Value::Blob(value.0.to_vec()))
            }
        }
    };
}

impl_blob32_key!(EncryptionPrivateKey);
impl_blob32_key!(EncryptionPublicKey);
impl_blob32_key!(NotePrivateKey);
impl_blob32_key!(NotePublicKey);

// ---- write side: satisfies Turso's blanket `IntoValue for T: TryInto<Value>`

impl TryFrom<NoteAmount> for Value {
    type Error = SqlError;

    fn try_from(value: NoteAmount) -> Result<Self, SqlError> {
        Ok(Value::Text(u128::from(value).to_string()))
    }
}

impl TryFrom<ExtAmount> for Value {
    type Error = SqlError;

    fn try_from(value: ExtAmount) -> Result<Self, SqlError> {
        let v = i64::try_from(i128::from(value)).map_err(|_| {
            SqlError::ConversionFailure(format!(
                "ExtAmount {} out of range for i64",
                i128::from(value)
            ))
        })?;
        Ok(Value::Integer(v))
    }
}

impl TryFrom<Field> for Value {
    type Error = SqlError;

    fn try_from(value: Field) -> Result<Self, SqlError> {
        Ok(Value::Blob(value.to_le_bytes().to_vec()))
    }
}

/// `&T` is accepted anywhere `T` is, so callers can pass borrowed params
/// (rusqlite's `ToSql` took `&self`; Turso's `TryInto<Value>` takes by value).
macro_rules! impl_ref_value {
    ($ty:ident) => {
        impl TryFrom<&$ty> for Value {
            type Error = SqlError;

            fn try_from(value: &$ty) -> Result<Self, SqlError> {
                Value::try_from(value.clone())
            }
        }
    };
}

impl_ref_value!(NoteAmount);
impl_ref_value!(ExtAmount);
impl_ref_value!(Field);
impl_ref_value!(EncryptionPrivateKey);
impl_ref_value!(EncryptionPublicKey);
impl_ref_value!(NotePrivateKey);
impl_ref_value!(NotePublicKey);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversion_errors_do_not_include_stored_values() {
        let secret = "private-key-material";
        let errors = [
            NotePrivateKey::from_value(Value::Text(secret.into()))
                .expect_err("invalid stored value"),
            EncryptionPrivateKey::from_value(Value::Text(secret.into()))
                .expect_err("invalid stored value"),
            NoteAmount::from_value(Value::Text(secret.into())).expect_err("invalid stored value"),
            Field::from_value(Value::Text(secret.into())).expect_err("invalid stored value"),
        ];
        for error in errors {
            assert!(!error.to_string().contains(secret));
        }
    }

    #[test]
    fn field_round_trips_as_le_blob() {
        let f = Field::try_from(ExtAmount::from(-1_i128)).expect("field");
        let v = Value::try_from(f).expect("to value");
        assert!(matches!(&v, Value::Blob(b) if b.len() == 32));
        assert_eq!(Field::from_value(v).expect("back"), f);
    }

    #[test]
    fn note_amount_round_trips_as_text() {
        let n = NoteAmount::from(42_u128);
        let v = Value::try_from(n).expect("to value");
        assert_eq!(v, Value::Text("42".to_string()));
        assert_eq!(u128::from(NoteAmount::from_value(v).expect("back")), 42);
    }

    #[test]
    fn ext_amount_round_trips_as_integer() {
        let e = ExtAmount::from(-1_i128);
        let v = Value::try_from(e).expect("to value");
        assert_eq!(v, Value::Integer(-1));
        assert_eq!(i128::from(ExtAmount::from_value(v).expect("back")), -1);
    }

    #[test]
    fn key_round_trips_as_blob32() {
        let k = NotePublicKey([7u8; 32]);
        let v = Value::try_from(k).expect("to value");
        assert!(matches!(&v, Value::Blob(b) if b.len() == 32));
        assert_eq!(NotePublicKey::from_value(v).expect("back").0, [7u8; 32]);
    }

    #[test]
    fn null_maps_to_none() {
        assert_eq!(
            Option::<String>::from_value(Value::Null).expect("null"),
            None
        );
        assert_eq!(
            Option::<String>::from_value(Value::Text("x".into())).expect("some"),
            Some("x".to_string())
        );
    }

    #[test]
    fn wrong_blob_size_is_rejected() {
        assert!(Field::from_value(Value::Blob(vec![0u8; 8])).is_err());
        assert!(NotePublicKey::from_value(Value::Blob(vec![0u8; 8])).is_err());
    }
}
