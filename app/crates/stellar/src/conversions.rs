use stellar_strkey::ed25519;
use stellar_xdr::curr::{
    self as xdr
};
use num_bigint::BigUint;
use crate::rpc::Error;

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
            _ => Err(Error::UnexpectedScVal(format!("Unsupported Address type: {addr:?}"))),
        }
    } else {
        Err(Error::UnexpectedScVal(format!("{val:?}")))
    }
}

/// Helper to convert U256Parts to BigUint
pub fn scval_to_u256(val: &xdr::ScVal) -> Result<BigUint, Error> {
    if let xdr::ScVal::U256(parts) = val {
        let hi_hi = BigUint::from(parts.hi_hi);
        let hi_lo = BigUint::from(parts.hi_lo);
        let lo_hi = BigUint::from(parts.lo_hi);
        let lo_lo = BigUint::from(parts.lo_lo);

        let total: BigUint = (hi_hi << 192) + (hi_lo << 128) + (lo_hi << 64) + lo_lo;

        Ok(total)
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
