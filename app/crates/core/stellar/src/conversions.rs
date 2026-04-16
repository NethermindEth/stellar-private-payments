use crate::rpc::Error;
use std::collections::HashMap;
use stellar_strkey::ed25519;
use stellar_xdr::curr::{self as xdr, ReadXdr};
use types::{ContractEvent, U256};

/// Helper to convert ScVal Address to G... or C... string
pub fn scval_to_address_string(val: &xdr::ScVal) -> Result<String, Error> {
    if let xdr::ScVal::Address(addr) = val {
        match addr {
            xdr::ScAddress::Account(account_id) => {
                // AccountId -> PublicKey enum -> PublicKeyTypeEd25519 variant -> Uint256
                let xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(bytes)) = &account_id.0;
                Ok(ed25519::PublicKey(*bytes).to_string())
            }
            xdr::ScAddress::Contract(contract_id) => {
                let bytes = contract_id.0.0;
                Ok(stellar_strkey::Contract(bytes).to_string())
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

/// Helper to convert ScVal Bytes to a Vec<u8>
pub fn scval_to_bytes(val: &xdr::ScVal) -> Result<Vec<u8>, Error> {
    if let xdr::ScVal::Bytes(sc_bytes) = val {
        Ok(sc_bytes.0.to_vec())
    } else {
        Err(Error::UnexpectedScVal(format!(
            "Expected ScVal::Bytes for encrypted_output, found: {:?}",
            val
        )))
    }
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

        Ok((hi_hi << 192) + (hi_lo << 128) + (lo_hi << 64) + lo_lo)
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
    let first = iter.next().ok_or_else(|| xdr::Error::Invalid)?;

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
