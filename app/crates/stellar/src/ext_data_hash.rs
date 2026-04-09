use sha3::{Digest, Keccak256};
use stellar_xdr::next::{
    Address, Int256, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr,
};
use std::convert::TryInto;
use std::str::FromStr;
use types::{BN254_MODULUS_BE, U256};
use types::ExtAmount;

pub struct ExtData {
    pub recipient: String,
    /// Signed external amount (stroops).
    pub ext_amount: ExtAmount, // Matches the I256 requirement
    pub encrypted_output0: Vec<u8>,
    pub encrypted_output1: Vec<u8>,
}

// please refer to hash_ext_data in contracts/pool/src/pool.rs
pub fn hash_ext_data_offchain(ext: &ExtData) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // 1. Prepare ScVal entries
    // Soroban structs serialize to XDR Maps sorted alphabetically by key
    let mut entries = vec![
        ("encrypted_output0", ScVal::Bytes(ext.encrypted_output0.clone().try_into()?)),
        ("encrypted_output1", ScVal::Bytes(ext.encrypted_output1.clone().try_into()?)),
        ("ext_amount", i128_to_i256_scval(ext.ext_amount.as_i128())),
        ("recipient", ScVal::Address(Address::from_str(&ext.recipient)?)),
    ];

    // 2. Sort by key alphabetically
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let sc_map = ScMap(entries
        .into_iter()
        .map(|(k, v)| ScMapEntry {
            key: ScVal::Symbol(ScSymbol(k.try_into().unwrap())),
            val: v,
        })
        .collect::<Vec<_>>()
        .try_into()?);

    let sc_val = ScVal::Map(Some(sc_map));

    // 3. Serialize to XDR
    let payload = sc_val.to_xdr()?;

    // 4. Keccak256 Hash
    let mut hasher = Keccak256::new();
    hasher.update(&payload);
    let digest = hasher.finalize();

    // 5. Modular arithmetic in the BN254 scalar field.
    //
    // Soroban's on-chain logic reduces a 256-bit hash modulo the field order. We mirror
    // that behavior off-chain using `types::U256` to avoid `num-bigint`.
    let mut digest_be = [0u8; 32];
    digest_be.copy_from_slice(digest.as_slice());
    let digest_u256 = U256::from_big_endian(&digest_be);
    let modulus = U256::from_big_endian(&BN254_MODULUS_BE);
    let reduced = digest_u256 % modulus;

    // 6. Convert to 32-byte big-endian array.
    let mut result_bytes = [0u8; 32];
    reduced.to_big_endian(&mut result_bytes);
    Ok(result_bytes)
}

/// Correctly maps i128 to Soroban's I256 XDR representation
fn i128_to_i256_scval(n: i128) -> ScVal {
    let hi = if n < 0 { -1i64 } else { 0i64 };
    ScVal::I256(Int256 {
        hi_hi: hi,
        hi_lo: hi as u64,
        lo_hi: (n >> 64) as u64,
        lo_lo: n as u64,
    })
}
