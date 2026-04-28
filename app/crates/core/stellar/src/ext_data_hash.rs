use anyhow::Result;
use core::ops::Rem;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
use stellar_xdr::curr::{
    Int256Parts, Limits, ScAddress, ScMap, ScMapEntry, ScSymbol, ScVal, WriteXdr,
};
use types::{BN254_MODULUS_BE, ExtData, U256};

// please refer to hash_ext_data in contracts/pool/src/pool.rs
pub fn hash_ext_data_offchain(ext: &ExtData) -> Result<[u8; 32]> {
    // 1. Prepare ScVal entries
    // Soroban structs serialize to XDR Maps sorted alphabetically by key
    let mut entries: Vec<(&str, ScVal)> = vec![
        (
            "encrypted_output0",
            ScVal::Bytes(ext.encrypted_output0.clone().try_into()?),
        ),
        (
            "encrypted_output1",
            ScVal::Bytes(ext.encrypted_output1.clone().try_into()?),
        ),
        ("ext_amount", i128_to_i256_scval(ext.ext_amount.into())),
        (
            "recipient",
            ScVal::Address(ext.recipient.parse::<ScAddress>()?),
        ),
    ];

    // 2. Sort by key alphabetically
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut map_entries: Vec<ScMapEntry> = Vec::with_capacity(entries.len());
    for (k, v) in entries {
        let sym: stellar_xdr::curr::StringM<32> = k.try_into()?;
        map_entries.push(ScMapEntry {
            key: ScVal::Symbol(ScSymbol(sym)),
            val: v,
        });
    }
    let sc_map = ScMap(map_entries.try_into()?);

    let sc_val = ScVal::Map(Some(sc_map));

    // 3. Serialize to XDR
    let payload = sc_val.to_xdr(Limits::none())?;

    // 4. Keccak256 Hash
    let mut hasher = Keccak256::new();
    hasher.update(&payload);
    let digest = hasher.finalize();

    // 5. Modular arithmetic in the BN254 scalar field.
    //
    // Soroban's on-chain logic reduces a 256-bit hash modulo the field order. We
    // mirror that behavior off-chain using `types::U256`.
    let mut digest_be = [0u8; 32];
    digest_be.copy_from_slice(digest.as_slice());
    let digest_u256 = U256::from_big_endian(&digest_be);
    let modulus = U256::from_big_endian(&BN254_MODULUS_BE);
    let reduced = Rem::rem(digest_u256, modulus);

    // 6. Convert to 32-byte big-endian array.
    let mut result_bytes = [0u8; 32];
    reduced.to_big_endian(&mut result_bytes);
    Ok(result_bytes)
}

/// Correctly maps i128 to Soroban's I256 XDR representation
fn i128_to_i256_scval(n: i128) -> ScVal {
    let hi = if n < 0 { -1i64 } else { 0i64 };
    let hi_lo = u64::from_be_bytes(hi.to_be_bytes());
    let bytes = n.to_be_bytes();
    let lo_hi = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let lo_lo = u64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    ScVal::I256(Int256Parts {
        hi_hi: hi,
        hi_lo,
        lo_hi,
        lo_lo,
    })
}
