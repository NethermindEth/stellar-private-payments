//! Off-chain Soroban `ScVal` encoding for pool contract calls.

use anyhow::{Result, anyhow};
use std::convert::TryInto;
use stellar_xdr::curr::{self as xdr, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal};
use types::{ExtData, Field};

use crate::ext_data_hash::i128_to_i256_scval;

/// Stellar base fee (stroops) used as the classic component before resource fees.
pub const BASE_FEE: u32 = 100;

pub fn field_to_scval_u256(v: Field) -> ScVal {
    let be = v.to_be_bytes();

    let hi_hi = u64::from_be_bytes(be[0..8].try_into().expect("U256 hi_hi slice"));
    let hi_lo = u64::from_be_bytes(be[8..16].try_into().expect("U256 hi_lo slice"));
    let lo_hi = u64::from_be_bytes(be[16..24].try_into().expect("U256 lo_hi slice"));
    let lo_lo = u64::from_be_bytes(be[24..32].try_into().expect("U256 lo_lo slice"));

    ScVal::U256(xdr::UInt256Parts {
        hi_hi,
        hi_lo,
        lo_hi,
        lo_lo,
    })
}

fn bytes_to_scval(bytes: impl AsRef<[u8]>) -> Result<ScVal> {
    Ok(ScVal::Bytes(bytes.as_ref().to_vec().try_into()?))
}

fn map_entry(key: &str, val: ScVal) -> Result<ScMapEntry> {
    let sym: xdr::StringM<32> = key.try_into().map_err(|_| anyhow!("invalid map key"))?;
    Ok(ScMapEntry {
        key: ScVal::Symbol(ScSymbol(sym)),
        val,
    })
}

fn sorted_map(entries: Vec<ScMapEntry>) -> Result<ScVal> {
    let mut entries = entries;
    entries.sort_by(|a, b| {
        let ScVal::Symbol(ka) = &a.key else {
            return std::cmp::Ordering::Equal;
        };
        let ScVal::Symbol(kb) = &b.key else {
            return std::cmp::Ordering::Equal;
        };
        ka.to_string().cmp(&kb.to_string())
    });
    Ok(ScVal::Map(Some(ScMap(entries.try_into()?))))
}

/// Encodes an uncompressed Groth16 proof (256 bytes) as a contract `Groth16Proof` map.
pub fn groth16_proof_to_scval(proof_uncompressed: &[u8]) -> Result<ScVal> {
    if proof_uncompressed.len() != 256 {
        return Err(anyhow!(
            "proof_uncompressed must be 256 bytes, got {}",
            proof_uncompressed.len()
        ));
    }
    sorted_map(vec![
        map_entry("a", bytes_to_scval(&proof_uncompressed[0..64])?)?,
        map_entry("b", bytes_to_scval(&proof_uncompressed[64..192])?)?,
        map_entry("c", bytes_to_scval(&proof_uncompressed[192..256])?)?,
    ])
}

/// Encodes pool `Proof` public inputs + embedded proof for `transact`.
#[allow(clippy::too_many_arguments)]
pub fn pool_proof_to_scval(
    proof_uncompressed: &[u8],
    root: Field,
    input_nullifiers: [Field; 2],
    output_commitment0: Field,
    output_commitment1: Field,
    public_amount: Field,
    ext_data_hash_be: [u8; 32],
    asp_membership_root: Field,
    asp_non_membership_root: Field,
) -> Result<ScVal> {
    let nullifiers = xdr::ScVec::try_from(vec![
        field_to_scval_u256(input_nullifiers[0]),
        field_to_scval_u256(input_nullifiers[1]),
    ])?;

    sorted_map(vec![
        map_entry(
            "asp_membership_root",
            field_to_scval_u256(asp_membership_root),
        )?,
        map_entry(
            "asp_non_membership_root",
            field_to_scval_u256(asp_non_membership_root),
        )?,
        map_entry("ext_data_hash", bytes_to_scval(ext_data_hash_be)?)?,
        map_entry("input_nullifiers", ScVal::Vec(Some(nullifiers)))?,
        map_entry(
            "output_commitment0",
            field_to_scval_u256(output_commitment0),
        )?,
        map_entry(
            "output_commitment1",
            field_to_scval_u256(output_commitment1),
        )?,
        map_entry("proof", groth16_proof_to_scval(proof_uncompressed)?)?,
        map_entry("public_amount", field_to_scval_u256(public_amount))?,
        map_entry("root", field_to_scval_u256(root))?,
    ])
}

/// Encodes pool `ExtData` for `transact`.
pub fn pool_ext_data_to_scval(ext: &ExtData) -> Result<ScVal> {
    sorted_map(vec![
        map_entry("encrypted_output0", bytes_to_scval(&ext.encrypted_output0)?)?,
        map_entry("encrypted_output1", bytes_to_scval(&ext.encrypted_output1)?)?,
        map_entry("ext_amount", i128_to_i256_scval(ext.ext_amount.into()))?,
        map_entry(
            "recipient",
            ScVal::Address(ext.recipient.parse::<ScAddress>()?),
        )?,
    ])
}

/// Encodes pool `Account` for `register`.
pub fn pool_account_to_scval(
    owner: &str,
    encryption_key: [u8; 32],
    note_key: [u8; 32],
) -> Result<ScVal> {
    sorted_map(vec![
        map_entry("encryption_key", bytes_to_scval(encryption_key)?)?,
        map_entry("note_key", bytes_to_scval(note_key)?)?,
        map_entry("owner", ScVal::Address(owner.parse::<ScAddress>()?))?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groth16_proof_encoding_length() {
        let proof = vec![0u8; 256];
        let sc = groth16_proof_to_scval(&proof).expect("encode proof");
        assert!(matches!(sc, ScVal::Map(Some(_))));
    }
}
