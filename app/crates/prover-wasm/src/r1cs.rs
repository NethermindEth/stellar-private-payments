//! R1CS Parser for Circom binary format
//!
//! Parses the `.r1cs` file format produced by the Circom compiler.
//! This allows us to replay constraints during proof generation.
//!
//! # File Format
//! The R1CS binary format consists of:
//! - Header with magic number "r1cs"
//! - Sections for header info, constraints, and wire mappings
//!
//! # Reference
//! https://github.com/iden3/r1csfile/blob/master/doc/r1cs_bin_format.md

use alloc::format;
use alloc::vec::Vec;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use wasm_bindgen::JsValue;

/// A term in a linear combination: coefficient * wire
#[derive(Clone, Debug)]
pub struct Term {
    /// Wire index (variable index in the constraint system)
    pub wire_id: u32,
    /// Coefficient as a field element
    pub coefficient: Fr,
}

/// A linear combination: sum of (coefficient * wire)
#[derive(Clone, Debug, Default)]
pub struct LinearCombination {
    /// The terms in this linear combination
    pub terms: Vec<Term>,
}

/// A single R1CS constraint: A * B = C
/// Where A, B, C are linear combinations
#[derive(Clone, Debug)]
pub struct Constraint {
    /// Linear combination A
    pub a: LinearCombination,
    /// Linear combination B  
    pub b: LinearCombination,
    /// Linear combination C
    pub c: LinearCombination,
}

/// Parsed R1CS file
#[derive(Clone, Debug)]
pub struct R1CS {
    /// Number of wires (variables) in the circuit
    pub num_wires: u32,
    /// Number of public outputs
    pub num_pub_out: u32,
    /// Number of public inputs
    pub num_pub_in: u32,
    /// Number of private inputs
    pub num_prv_in: u32,
    /// Total number of public inputs (outputs + inputs, excluding constant 1)
    pub num_public: u32,
    /// The constraints
    pub constraints: Vec<Constraint>,
}

impl R1CS {
    /// Parse R1CS from binary data
    pub fn parse(data: &[u8]) -> Result<Self, JsValue> {
        let mut cursor = Cursor::new(data);

        // Read and verify magic number "r1cs"
        let magic = cursor.read_bytes(4)?;
        if magic != b"r1cs" {
            return Err(JsValue::from_str("Invalid R1CS magic number"));
        }

        // Version (should be 1)
        let version = cursor.read_u32_le()?;
        if version != 1 {
            return Err(JsValue::from_str(&format!(
                "Unsupported R1CS version: {}",
                version
            )));
        }

        // Number of sections
        let num_sections = cursor.read_u32_le()?;

        let mut header: Option<R1CSHeader> = None;
        let mut constraints_data: Option<(usize, usize)> = None; // (start, size)

        // First pass: collect section locations
        for _ in 0..num_sections {
            let section_type = cursor.read_u32_le()?;
            let section_size = cursor.read_u64_le()?;
            let section_start = cursor.position;

            match section_type {
                1 => {
                    // Header section
                    header = Some(Self::parse_header(&mut cursor)?);
                }
                2 => {
                    // Constraints section - save location for later
                    constraints_data = Some((section_start, section_size as usize));
                    cursor.skip(section_size as usize)?;
                }
                3 => {
                    // Wire2LabelId section - skip
                    cursor.skip(section_size as usize)?;
                }
                _ => {
                    // Unknown section - skip
                    cursor.skip(section_size as usize)?;
                }
            }

            // Ensure we consumed exactly section_size bytes
            let consumed = cursor.position - section_start;
            if consumed < section_size as usize {
                cursor.skip((section_size as usize) - consumed)?;
            }
        }

        // Now parse constraints with header available
        let header = header.ok_or_else(|| JsValue::from_str("Missing R1CS header section"))?;
        
        let constraints = if let Some((start, _size)) = constraints_data {
            cursor.position = start;
            Self::parse_constraints(&mut cursor, &header)?
        } else {
            Vec::new()
        };

        // num_public = num_pub_out + num_pub_in (not including the constant 1 wire)
        let num_public = header.num_pub_out + header.num_pub_in;

        Ok(R1CS {
            num_wires: header.num_wires,
            num_pub_out: header.num_pub_out,
            num_pub_in: header.num_pub_in,
            num_prv_in: header.num_prv_in,
            num_public,
            constraints,
        })
    }

    fn parse_header(cursor: &mut Cursor) -> Result<R1CSHeader, JsValue> {
        // Field size in bytes (should be 32 for BN254)
        let field_size = cursor.read_u32_le()?;
        if field_size != 32 {
            return Err(JsValue::from_str(&format!(
                "Unsupported field size: {} (expected 32)",
                field_size
            )));
        }

        // Prime (skip - we assume BN254)
        cursor.skip(field_size as usize)?;

        let num_wires = cursor.read_u32_le()?;
        let num_pub_out = cursor.read_u32_le()?;
        let num_pub_in = cursor.read_u32_le()?;
        let num_prv_in = cursor.read_u32_le()?;
        let _num_labels = cursor.read_u64_le()?;
        let num_constraints = cursor.read_u32_le()?;

        Ok(R1CSHeader {
            field_size,
            num_wires,
            num_pub_out,
            num_pub_in,
            num_prv_in,
            num_constraints,
        })
    }

    fn parse_constraints(cursor: &mut Cursor, header: &R1CSHeader) -> Result<Vec<Constraint>, JsValue> {
        let mut constraints = Vec::with_capacity(header.num_constraints as usize);

        for _ in 0..header.num_constraints {
            let a = Self::parse_linear_combination(cursor, header.field_size)?;
            let b = Self::parse_linear_combination(cursor, header.field_size)?;
            let c = Self::parse_linear_combination(cursor, header.field_size)?;

            constraints.push(Constraint { a, b, c });
        }

        Ok(constraints)
    }

    fn parse_linear_combination(cursor: &mut Cursor, field_size: u32) -> Result<LinearCombination, JsValue> {
        let num_terms = cursor.read_u32_le()?;
        let mut terms = Vec::with_capacity(num_terms as usize);

        for _ in 0..num_terms {
            let wire_id = cursor.read_u32_le()?;
            let coeff_bytes = cursor.read_bytes(field_size as usize)?;
            let coefficient = Fr::from_le_bytes_mod_order(coeff_bytes);

            terms.push(Term {
                wire_id,
                coefficient,
            });
        }

        Ok(LinearCombination { terms })
    }

    /// Get total number of constraints
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }
}

/// Internal header struct
struct R1CSHeader {
    field_size: u32,
    num_wires: u32,
    num_pub_out: u32,
    num_pub_in: u32,
    num_prv_in: u32,
    num_constraints: u32,
}

/// Simple cursor for reading binary data
struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, position: 0 }
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], JsValue> {
        if self.position + n > self.data.len() {
            return Err(JsValue::from_str("Unexpected end of R1CS data"));
        }
        let slice = &self.data[self.position..self.position + n];
        self.position += n;
        Ok(slice)
    }

    fn read_u32_le(&mut self) -> Result<u32, JsValue> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, JsValue> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn skip(&mut self, n: usize) -> Result<(), JsValue> {
        if self.position + n > self.data.len() {
            return Err(JsValue::from_str("Unexpected end of R1CS data"));
        }
        self.position += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_reads() {
        let data = [0x72, 0x31, 0x63, 0x73, 0x01, 0x00, 0x00, 0x00]; // "r1cs" + version 1
        let mut cursor = Cursor::new(&data);
        
        let magic = cursor.read_bytes(4).unwrap();
        assert_eq!(magic, b"r1cs");
        
        let version = cursor.read_u32_le().unwrap();
        assert_eq!(version, 1);
    }
}

