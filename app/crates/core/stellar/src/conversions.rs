use crate::rpc::Error;
use core::ops::Shl;
use std::{collections::HashMap, convert::TryInto};
use stellar_strkey::ed25519;
use stellar_xdr::curr::{self as xdr, Int256Parts, ReadXdr};
use types::{ContractEvent, Field, U256};

/// Helper to convert ScVal Address to G... or C... string
pub fn scval_to_address_string(val: &xdr::ScVal) -> Result<String, Error> {
    if let xdr::ScVal::Address(addr) = val {
        match addr {
            xdr::ScAddress::Account(account_id) => {
                // AccountId -> PublicKey enum -> PublicKeyTypeEd25519 variant -> Uint256
                let xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(bytes)) = &account_id.0;
                Ok(ed25519::PublicKey(*bytes).to_string().as_str().to_string())
            }
            xdr::ScAddress::Contract(contract_id) => {
                let bytes = contract_id.0.0;
                Ok(stellar_strkey::Contract(bytes)
                    .to_string()
                    .as_str()
                    .to_string())
            }
            // Handling MuxedAccount, ClaimableBalance, and LiquidityPool
            _ => Err(Error::UnexpectedScVal(format!(
                "Unsupported Address type: {addr:?}"
            ))),
        }
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

/// Helper to convert ScVal Bytes to a `Vec<u8>`
pub fn scval_to_bytes(val: &xdr::ScVal) -> Result<Vec<u8>, Error> {
    if let xdr::ScVal::Bytes(sc_bytes) = val {
        Ok(sc_bytes.0.to_vec())
    } else {
        Err(Error::UnexpectedScVal(format!(
            "Expected ScVal::Bytes, found: {val:?}"
        )))
    }
}

/// Encodes a BN254 field element as Soroban `ScVal::U256`.
pub fn field_to_scval_u256(v: Field) -> xdr::ScVal {
    let be = v.to_be_bytes();

    let hi_hi = u64::from_be_bytes(be[0..8].try_into().expect("U256 hi_hi slice"));
    let hi_lo = u64::from_be_bytes(be[8..16].try_into().expect("U256 hi_lo slice"));
    let lo_hi = u64::from_be_bytes(be[16..24].try_into().expect("U256 lo_lo slice"));
    let lo_lo = u64::from_be_bytes(be[24..32].try_into().expect("U256 lo_lo slice"));

    xdr::ScVal::U256(xdr::UInt256Parts {
        hi_hi,
        hi_lo,
        lo_hi,
        lo_lo,
    })
}

/// Encodes `i128` as Soroban `ScVal::I256` (two's-complement XDR layout).
pub fn i128_to_i256_scval(n: i128) -> xdr::ScVal {
    let hi = if n < 0 { -1i64 } else { 0i64 };
    let hi_lo = u64::from_be_bytes(hi.to_be_bytes());
    let bytes = n.to_be_bytes();
    let lo_hi = u64::from_be_bytes(bytes[0..8].try_into().expect("i128 lo_hi slice"));
    let lo_lo = u64::from_be_bytes(bytes[8..16].try_into().expect("i128 lo_lo slice"));
    xdr::ScVal::I256(Int256Parts {
        hi_hi: hi,
        hi_lo,
        lo_hi,
        lo_lo,
    })
}

/// Encodes bytes as Soroban `ScVal::Bytes`.
pub fn bytes_to_scval(bytes: impl AsRef<[u8]>) -> Result<xdr::ScVal, Error> {
    Ok(xdr::ScVal::Bytes(
        bytes
            .as_ref()
            .to_vec()
            .try_into()
            .map_err(|_| Error::UnexpectedScVal("bytes too long for ScVal::Bytes".into()))?,
    ))
}

/// Helper to convert Soroban `U256` parts into a `types::U256`.
pub fn scval_to_u256(val: &xdr::ScVal) -> Result<U256, Error> {
    if let xdr::ScVal::U256(parts) = val {
        // Soroban encodes U256 as 4x u64 limbs, big-endian by limb significance.
        // Reconstruct as: hi_hi<<192 + hi_lo<<128 + lo_hi<<64 + lo_lo.
        let hi_hi = U256::from(parts.hi_hi);
        let hi_lo = U256::from(parts.hi_lo);
        let lo_hi = U256::from(parts.lo_hi);
        let lo_lo = U256::from(parts.lo_lo);

        let mut out = Shl::shl(hi_hi, 192);
        out = out
            .checked_add(Shl::shl(hi_lo, 128))
            .ok_or_else(|| Error::UnexpectedScVal("U256 overflow (hi_lo)".into()))?;
        out = out
            .checked_add(Shl::shl(lo_hi, 64))
            .ok_or_else(|| Error::UnexpectedScVal("U256 overflow (lo_hi)".into()))?;
        out = out
            .checked_add(lo_lo)
            .ok_or_else(|| Error::UnexpectedScVal("U256 overflow (lo_lo)".into()))?;
        Ok(out)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

pub fn scval_to_u32(val: &xdr::ScVal) -> Result<u32, Error> {
    if let xdr::ScVal::U32(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

pub fn scval_to_u64(val: &xdr::ScVal) -> Result<u64, Error> {
    if let xdr::ScVal::U64(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

pub fn scval_to_bool(val: &xdr::ScVal) -> Result<bool, Error> {
    if let xdr::ScVal::Bool(n) = val {
        Ok(*n)
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

#[derive(Debug)]
pub struct ParsedContractEvent {
    // Unique identifier for this event, based on the TOID format.
    // It combines a 19-character TOID and a 10-character, zero-padded event index, separated by a
    // hyphen.
    pub id: String,
    // Sequence number of the ledger in which this event was emitted
    pub ledger: u32,
    // StrKey representation of the contract address that emitted this event.
    pub contract_id: String,
    // The name of the event, snake_case. It is topic[0].
    pub name: String,
    pub topics: Vec<xdr::ScVal>,
    // Mapping field name - value
    pub values: HashMap<String, xdr::ScVal>,
}

pub fn parse_event_metadata(event: ContractEvent) -> Result<ParsedContractEvent, Error> {
    let ContractEvent {
        id,
        ledger,
        contract_id,
        topics,
        value,
    } = event;

    let mut iter = topics.iter();
    let first = iter.next().ok_or(xdr::Error::Invalid)?;

    let topics: Vec<xdr::ScVal> = iter
        .map(|s| xdr::ScVal::from_xdr_base64(s, xdr::Limits::none()))
        .collect::<Result<_, _>>()?;

    let name = match xdr::ScVal::from_xdr_base64(first, xdr::Limits::none())? {
        xdr::ScVal::Symbol(sym) => sym.to_utf8_string()?,
        _ => {
            return Err(Error::UnexpectedScVal(
                "the first topic of an event should be a symbol".into(),
            ));
        }
    };

    let data = xdr::ScVal::from_xdr_base64(value, xdr::Limits::none())?;

    let mut values = HashMap::new();

    // https://docs.rs/soroban-sdk/latest/soroban_sdk/attr.contractevent.html
    match data {
        xdr::ScVal::Map(Some(map)) => {
            for xdr::ScMapEntry { key, val } in map.iter() {
                let field_name = match key {
                    xdr::ScVal::Symbol(sym) => sym.to_utf8_string()?,
                    _ => {
                        return Err(Error::UnexpectedScVal(format!(
                            "event data field name should be a symbol: {key:?}"
                        )));
                    }
                };
                values.insert(field_name, val.clone());
            }
        }
        xdr::ScVal::Void => {}
        _ => {
            return Err(Error::UnexpectedScVal(
                "an event data format should be a map".into(),
            ));
        }
    };

    Ok(ParsedContractEvent {
        id,
        ledger,
        contract_id,
        name,
        topics,
        values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Field, U256};

    #[test]
    fn field_u256_scval_roundtrip() {
        let field = Field(U256::from(0xDEAD_BEEF_u64));
        let sc = field_to_scval_u256(field);
        let back = scval_to_u256(&sc).expect("decode u256");
        assert_eq!(back, field.0);
    }
}
