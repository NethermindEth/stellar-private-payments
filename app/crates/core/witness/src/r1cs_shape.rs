use anyhow::{Context as _, Result, anyhow};

use crate::field::bn254_field_modulus_le_bytes;

#[derive(Debug)]
pub(crate) struct CircuitShape {
    pub(crate) witness_size: u32,
    pub(crate) num_public_inputs: u32,
}

pub(crate) fn parse_circuit_shape(r1cs_bytes: &[u8]) -> Result<CircuitShape> {
    let mut cursor = R1csCursor::new(r1cs_bytes);
    let magic = cursor.read_bytes(4)?;
    if magic != b"r1cs" {
        anyhow::bail!("Invalid R1CS magic number");
    }

    let version = cursor.read_u32_le()?;
    if version != 1 {
        anyhow::bail!("Unsupported R1CS version: {version}");
    }

    let num_sections = cursor.read_u32_le()?;
    for _ in 0..num_sections {
        let section_type = cursor.read_u32_le()?;
        let section_size = cursor.read_u64_le()?;
        let section_size =
            usize::try_from(section_size).context("R1CS section size does not fit usize")?;

        if section_type == 1 {
            let section_start = cursor.position;
            let field_size = cursor.read_u32_le()?;
            if field_size != 32 {
                anyhow::bail!("Unsupported R1CS field size: {field_size} (expected 32)");
            }
            let modulus = cursor.read_bytes(32)?;
            if modulus != bn254_field_modulus_le_bytes().as_slice() {
                anyhow::bail!("R1CS field modulus is not BN254");
            }

            let witness_size = cursor.read_u32_le()?;
            cursor.read_u32_le()?; // public outputs
            let num_public_inputs = cursor.read_u32_le()?;
            cursor.read_u32_le()?; // private inputs

            let consumed = cursor
                .position
                .checked_sub(section_start)
                .ok_or_else(|| anyhow!("Invalid R1CS cursor position"))?;
            let remaining = section_size
                .checked_sub(consumed)
                .ok_or_else(|| anyhow!("R1CS header exceeds section size"))?;
            cursor.skip(remaining)?;

            return Ok(CircuitShape {
                witness_size,
                num_public_inputs,
            });
        }

        cursor.skip(section_size)?;
    }

    anyhow::bail!("Missing R1CS header section")
}

struct R1csCursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> R1csCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| anyhow!("Overflow in R1CS cursor position"))?;
        if end > self.data.len() {
            anyhow::bail!("Unexpected end of R1CS data");
        }
        let bytes = &self.data[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn skip(&mut self, len: usize) -> Result<()> {
        self.read_bytes(len).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r1cs_shape_parser_reads_header_without_witness_runtime_dependencies() {
        let shape = parse_circuit_shape(&r1cs_header_bytes(3, 1))
            .expect("minimal R1CS header should parse");

        assert_eq!(shape.witness_size, 3);
        assert_eq!(shape.num_public_inputs, 1);
    }

    #[test]
    fn r1cs_shape_parser_rejects_non_bn254_field_modulus() {
        let mut r1cs = r1cs_header_bytes(3, 1);
        r1cs[28] ^= 1;

        let err = parse_circuit_shape(&r1cs).expect_err("non-BN254 R1CS must fail");

        assert!(
            err.to_string().contains("R1CS field modulus is not BN254"),
            "{err:#}"
        );
    }

    fn r1cs_header_bytes(num_wires: u32, num_pub_in: u32) -> Vec<u8> {
        const HEADER_SIZE: u64 = 64;

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"r1cs");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&HEADER_SIZE.to_le_bytes());
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&bn254_field_modulus_le_bytes());
        bytes.extend_from_slice(&num_wires.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&num_pub_in.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }
}
