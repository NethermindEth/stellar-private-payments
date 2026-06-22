use anyhow::{Result, anyhow};
use num_bigint::{BigInt, Sign};
use ruint::aliases::U256;
use std::collections::HashMap;

/// BN254 scalar field modulus.
pub(crate) const BN254_FIELD_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

pub(crate) fn to_field_element(bi: BigInt) -> Result<BigInt> {
    let modulus = bn254_field_modulus();

    if bi.sign() == Sign::Minus {
        let abs_value = bi
            .checked_mul(&BigInt::from(-1))
            .ok_or_else(|| anyhow!("Overflow in getting the abs value"))?;

        if abs_value >= modulus {
            anyhow::bail!("Negative value {bi} exceeds field modulus");
        }

        return modulus
            .checked_sub(&abs_value)
            .ok_or_else(|| anyhow!("Overflow in field element computation"));
    }

    if bi >= modulus {
        anyhow::bail!("Value {bi} exceeds field modulus");
    }
    Ok(bi)
}

pub(crate) fn bn254_field_modulus() -> BigInt {
    BigInt::parse_bytes(BN254_FIELD_MODULUS.as_bytes(), 10).expect("Invalid field modulus")
}

pub(crate) fn bn254_field_modulus_le_bytes() -> [u8; 32] {
    let bytes = bn254_field_modulus().to_bytes_le().1;
    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    padded
}

pub(crate) fn inputs_hashmap_to_u256(
    inputs: HashMap<String, Vec<BigInt>>,
) -> Result<HashMap<String, Vec<U256>>> {
    inputs
        .into_iter()
        .map(|(key, values)| {
            let converted = values
                .into_iter()
                .map(bigint_to_u256)
                .collect::<Result<Vec<_>>>()
                .map_err(|e| anyhow!("Invalid field element for {key}: {e}"))?;
            Ok((key, converted))
        })
        .collect()
}

pub(crate) fn bigint_to_u256(value: BigInt) -> Result<U256> {
    if value.sign() == Sign::Minus {
        anyhow::bail!("field element is negative");
    }

    let modulus = bn254_field_modulus();
    if value >= modulus {
        anyhow::bail!("field element is outside the BN254 scalar field");
    }

    let bytes = value.to_bytes_le().1;
    if bytes.len() > 32 {
        anyhow::bail!("field element exceeds 32 bytes");
    }

    let mut padded = [0u8; 32];
    padded[..bytes.len()].copy_from_slice(&bytes);
    Ok(U256::from_le_bytes(padded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_element_normalization_rejects_positive_modulus_instead_of_panicking() {
        let err = to_field_element(bn254_field_modulus())
            .expect_err("field modulus itself is not a canonical field element");

        assert!(err.to_string().contains("exceeds field modulus"), "{err:#}");
    }

    #[test]
    fn field_element_normalization_rejects_negative_modulus_instead_of_panicking() {
        let err = to_field_element(-bn254_field_modulus())
            .expect_err("negative modulus magnitude is not a field element");

        assert!(err.to_string().contains("exceeds field modulus"), "{err:#}");
    }

    #[test]
    fn graph_field_conversion_rejects_values_outside_bn254_scalar_field() {
        let err = bigint_to_u256(bn254_field_modulus())
            .expect_err("canonical graph inputs must stay inside the scalar field");

        assert!(
            err.to_string()
                .contains("field element is outside the BN254 scalar field"),
            "{err:#}"
        );
    }
}
