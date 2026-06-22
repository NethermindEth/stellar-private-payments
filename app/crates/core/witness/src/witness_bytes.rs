use num_bigint::{BigInt, Sign};
use ruint::aliases::U256;
use std::vec::Vec;

/// Convert witness to Little-Endian bytes (32 bytes per element).
pub(crate) fn witness_to_bytes(witness: &[BigInt]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("Overflow in witness size"),
    );

    for bi in witness {
        let (sign, be_bytes) = bi.to_bytes_be();

        assert!(
            be_bytes.len() <= 32,
            "Field element exceeds 32 bytes in witness"
        );
        assert!(
            sign != Sign::Minus,
            "Negative number in witness output - inputs should be field elements"
        );

        let mut padded = vec![0u8; 32];
        let offset = 32usize.saturating_sub(be_bytes.len());
        padded[offset..].copy_from_slice(&be_bytes);
        padded.reverse();
        bytes.extend_from_slice(&padded);
    }

    bytes
}

pub(crate) fn witness_u256_to_bytes(witness: &[U256]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        witness
            .len()
            .checked_mul(32)
            .expect("Overflow in witness size"),
    );

    for value in witness {
        bytes.extend_from_slice(&value.to_le_bytes::<32>());
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_witness_bytes_match_existing_little_endian_layout() {
        let graph_witness = vec![U256::from(1), U256::from(0x1234_u64)];
        let legacy_witness = vec![BigInt::from(1), BigInt::from(0x1234_u64)];

        assert_eq!(
            witness_u256_to_bytes(&graph_witness),
            witness_to_bytes(&legacy_witness)
        );
    }
}
