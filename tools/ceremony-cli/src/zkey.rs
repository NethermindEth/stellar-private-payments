// Vendored from arkworks-rs/circom-compat (MIT OR Apache-2.0), commit 09e92d4:
//   https://github.com/arkworks-rs/circom-compat/blob/09e92d4c5887cec9ea558dc7e775a8ab3b02aafc/src/zkey.rs
//   https://github.com/arkworks-rs/circom-compat/blob/09e92d4c5887cec9ea558dc7e775a8ab3b02aafc/src/index.rs (`NPIndex`)
//
// Local changes: only the proving key is read (the constraint matrices and
// `NPIndex` are dropped), point sections must match the size implied by the
// header, malformed headers, missing sections, non-canonical field elements
// and invalid curve points return errors instead of panicking,
// and the upstream test module (which needs the upstream test
// vectors and the wasmer witness calculator) is dropped.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_errors_doc
)]

//! ZKey Parsing
//!
//! Each ZKey file is broken into sections:
//!  Header(1)
//!       Prover Type 1 Groth
//!  HeaderGroth(2)
//!       n8q
//!       q
//!       n8r
//!       r
//!       NVars
//!       NPub
//!       DomainSize  (multiple of 2
//!       alpha1
//!       beta1
//!       delta1
//!       beta2
//!       gamma2
//!       delta2
//!  IC(3)
//!  Coefs(4)
//!  PointsA(5)
//!  PointsB1(6)
//!  PointsB2(7)
//!  PointsC(8)
//!  PointsH(9)
//!  Contributions(10)
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger256, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, SerializationError};
use ark_std::log2;
use byteorder::{LittleEndian, ReadBytesExt};
use num_traits::Zero;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
};

type IoResult<T> = Result<T, SerializationError>;

const ZKEY_MAGIC: &[u8; 4] = b"zkey";
const PROTOCOL_GROTH16: u32 = 1;
const G1_SIZE: u64 = 64;
const G2_SIZE: u64 = 128;

#[derive(Clone, Debug)]
struct Section {
    position: u64,
    size: u64,
}

/// Reads a SnarkJS ZKey file into an Arkworks ProvingKey.
pub fn read_zkey<R: Read + Seek>(reader: &mut R) -> IoResult<ProvingKey<Bn254>> {
    let mut binfile = BinFile::new(reader)?;
    binfile.check_protocol()?;
    binfile.proving_key()
}

#[derive(Debug)]
struct BinFile<'a, R> {
    #[allow(dead_code)]
    version: u32,
    sections: HashMap<u32, Vec<Section>>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != ZKEY_MAGIC {
            return Err(SerializationError::InvalidData);
        }

        let version = reader.read_u32::<LittleEndian>()?;

        let num_sections = reader.read_u32::<LittleEndian>()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32::<LittleEndian>()?;
            let section_length = reader.read_u64::<LittleEndian>()?;

            let section = sections.entry(section_id).or_insert_with(Vec::new);
            section.push(Section {
                position: reader.stream_position()?,
                size: section_length,
            });

            let skip =
                i64::try_from(section_length).map_err(|_| SerializationError::InvalidData)?;
            reader.seek(SeekFrom::Current(skip))?;
        }

        Ok(Self {
            version,
            sections,
            reader,
        })
    }

    fn check_protocol(&mut self) -> IoResult<()> {
        let section = self.get_section(1)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        if self.reader.read_u32::<LittleEndian>()? != PROTOCOL_GROTH16 {
            return Err(SerializationError::InvalidData);
        }
        Ok(())
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let ic = self.ic(header.n_public)?;

        let n_private = header
            .n_vars
            .checked_sub(header.n_public + 1)
            .ok_or(SerializationError::InvalidData)?;

        let a_query = self.a_query(header.n_vars)?;
        let b_g1_query = self.b_g1_query(header.n_vars)?;
        let b_g2_query = self.b_g2_query(header.n_vars)?;
        let l_query = self.l_query(n_private)?;
        let h_query = self.h_query(header.domain_size as usize)?;

        let vk = VerifyingKey::<Bn254> {
            alpha_g1: header.verifying_key.alpha_g1,
            beta_g2: header.verifying_key.beta_g2,
            gamma_g2: header.verifying_key.gamma_g2,
            delta_g2: header.verifying_key.delta_g2,
            gamma_abc_g1: ic,
        };

        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1: header.verifying_key.beta_g1,
            delta_g1: header.verifying_key.delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };

        Ok(pk)
    }

    fn get_section(&self, id: u32) -> IoResult<Section> {
        self.sections
            .get(&id)
            .and_then(|s| s.first())
            .cloned()
            .ok_or(SerializationError::InvalidData)
    }

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        let section = self.get_section(2)?;
        let header = HeaderGroth::new(&mut self.reader, &section)?;
        Ok(header)
    }

    fn ic(&mut self, n_public: usize) -> IoResult<Vec<G1Affine>> {
        // the range is non-inclusive so we do +1 to get all inputs
        self.g1_section(n_public + 1, 3)
    }

    fn a_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 5)
    }

    fn b_g1_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 6)
    }

    fn b_g2_query(&mut self, n_vars: usize) -> IoResult<Vec<G2Affine>> {
        self.g2_section(n_vars, 7)
    }

    fn l_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 8)
    }

    fn h_query(&mut self, n_vars: usize) -> IoResult<Vec<G1Affine>> {
        self.g1_section(n_vars, 9)
    }

    fn g1_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G1Affine>> {
        let num = self.seek_point_section(num, section_id, G1_SIZE)?;
        deserialize_g1_vec(self.reader, num)
    }

    fn g2_section(&mut self, num: usize, section_id: usize) -> IoResult<Vec<G2Affine>> {
        let num = self.seek_point_section(num, section_id, G2_SIZE)?;
        deserialize_g2_vec(self.reader, num)
    }

    /// Seeks to a section holding `num` points of `point_size` bytes each,
    /// rejecting it unless its length is exactly `num * point_size`.
    fn seek_point_section(
        &mut self,
        num: usize,
        section_id: usize,
        point_size: u64,
    ) -> IoResult<u32> {
        let section = self.get_section(section_id as u32)?;
        let num = u32::try_from(num).map_err(|_| SerializationError::InvalidData)?;
        if u64::from(num).checked_mul(point_size) != Some(section.size) {
            return Err(SerializationError::InvalidData);
        }
        self.reader.seek(SeekFrom::Start(section.position))?;
        Ok(num)
    }
}

#[derive(Default, Clone, Debug, CanonicalDeserialize)]
pub struct ZVerifyingKey {
    alpha_g1: G1Affine,
    beta_g1: G1Affine,
    beta_g2: G2Affine,
    gamma_g2: G2Affine,
    delta_g1: G1Affine,
    delta_g2: G2Affine,
}

impl ZVerifyingKey {
    fn new<R: Read>(reader: &mut R) -> IoResult<Self> {
        let alpha_g1 = deserialize_g1(reader)?;
        let beta_g1 = deserialize_g1(reader)?;
        let beta_g2 = deserialize_g2(reader)?;
        let gamma_g2 = deserialize_g2(reader)?;
        let delta_g1 = deserialize_g1(reader)?;
        let delta_g2 = deserialize_g2(reader)?;

        Ok(Self {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g1,
            delta_g2,
        })
    }
}

#[derive(Clone, Debug)]
struct HeaderGroth {
    #[allow(dead_code)]
    n8q: u32,
    #[allow(dead_code)]
    q: BigInteger256,
    #[allow(dead_code)]
    n8r: u32,
    #[allow(dead_code)]
    r: BigInteger256,

    n_vars: usize,
    n_public: usize,

    domain_size: u32,
    #[allow(dead_code)]
    power: u32,

    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
    fn new<R: Read + Seek>(reader: &mut R, section: &Section) -> IoResult<Self> {
        reader.seek(SeekFrom::Start(section.position))?;
        Self::read(reader)
    }

    fn read<R: Read>(mut reader: &mut R) -> IoResult<Self> {
        // TODO: Impl From<u32> in Arkworks
        let n8q: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // group order r of Bn254
        let q = BigInteger256::deserialize_uncompressed(&mut reader)?;

        let n8r: u32 = u32::deserialize_uncompressed(&mut reader)?;
        // Prime field modulus
        let r = BigInteger256::deserialize_uncompressed(&mut reader)?;
        if n8q != 32 || n8r != 32 || q != Fq::MODULUS || r != Fr::MODULUS {
            return Err(SerializationError::InvalidData);
        }

        let n_vars = u32::deserialize_uncompressed(&mut reader)? as usize;
        let n_public = u32::deserialize_uncompressed(&mut reader)? as usize;

        let domain_size: u32 = u32::deserialize_uncompressed(&mut reader)?;
        let power = log2(domain_size as usize);

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n8q,
            q,
            n8r,
            r,
            n_vars,
            n_public,
            domain_size,
            power,
            verifying_key,
        })
    }
}

// skips the multiplication by R because Circom points are already in Montgomery
// form
fn deserialize_field<R: Read>(reader: &mut R) -> IoResult<Fq> {
    let bigint = BigInteger256::deserialize_uncompressed(reader)?;
    if bigint >= Fq::MODULUS {
        return Err(SerializationError::InvalidData);
    }
    // if you use Fq::new it multiplies by R
    Ok(Fq::new_unchecked(bigint))
}

pub fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
    let c0 = deserialize_field(reader)?;
    let c1 = deserialize_field(reader)?;
    Ok(Fq2::new(c0, c1))
}

fn deserialize_g1<R: Read>(reader: &mut R) -> IoResult<G1Affine> {
    let x = deserialize_field(reader)?;
    let y = deserialize_field(reader)?;
    let infinity = x.is_zero() && y.is_zero();
    if infinity {
        return Ok(G1Affine::identity());
    }
    let point = G1Affine::new_unchecked(x, y);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    Ok(point)
}

fn deserialize_g2<R: Read>(reader: &mut R) -> IoResult<G2Affine> {
    let f1 = deserialize_field2(reader)?;
    let f2 = deserialize_field2(reader)?;
    let infinity = f1.is_zero() && f2.is_zero();
    if infinity {
        return Ok(G2Affine::identity());
    }
    let point = G2Affine::new_unchecked(f1, f2);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SerializationError::InvalidData);
    }
    Ok(point)
}

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G1Affine>> {
    (0..n_vars).map(|_| deserialize_g1(reader)).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: u32) -> IoResult<Vec<G2Affine>> {
    (0..n_vars).map(|_| deserialize_g2(reader)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{g1, g2};
    use ark_ff::{AdditiveGroup, Field};
    use ark_serialize::CanonicalSerialize;

    fn write_fq(out: &mut Vec<u8>, value: BigInteger256) {
        value.serialize_uncompressed(out).unwrap();
    }

    fn g1_bytes(point: &G1Affine) -> Vec<u8> {
        let mut out = Vec::new();
        write_fq(&mut out, point.x.0);
        write_fq(&mut out, point.y.0);
        out
    }

    fn g2_bytes(point: &G2Affine) -> Vec<u8> {
        let mut out = Vec::new();
        for c in [point.x.c0, point.x.c1, point.y.c0, point.y.c1] {
            write_fq(&mut out, c.0);
        }
        out
    }

    #[test]
    fn g1_roundtrip() {
        let g = G1Affine::new_unchecked(g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y);
        assert_eq!(deserialize_g1(&mut &g1_bytes(&g)[..]).unwrap(), g);
        let zero = [0u8; 64];
        assert_eq!(
            deserialize_g1(&mut &zero[..]).unwrap(),
            G1Affine::identity()
        );
    }

    #[test]
    fn g1_rejects_off_curve_point() {
        let point = G1Affine::new_unchecked(Fq::ONE, Fq::ONE);
        assert!(deserialize_g1(&mut &g1_bytes(&point)[..]).is_err());
    }

    #[test]
    fn g1_rejects_non_canonical_coordinate() {
        let mut bytes = Vec::new();
        write_fq(&mut bytes, Fq::MODULUS);
        write_fq(&mut bytes, Fq::ONE.0);
        assert!(deserialize_g1(&mut &bytes[..]).is_err());
    }

    #[test]
    fn g2_roundtrip() {
        let g = G2Affine::new_unchecked(g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y);
        assert_eq!(deserialize_g2(&mut &g2_bytes(&g)[..]).unwrap(), g);
    }

    #[test]
    fn g2_rejects_point_outside_subgroup() {
        let mut x = Fq2::ZERO;
        let point = loop {
            x += Fq2::ONE;
            if let Some(p) = G2Affine::get_point_from_x_unchecked(x, false) {
                break p;
            }
        };
        assert!(point.is_on_curve());
        assert!(!point.is_in_correct_subgroup_assuming_on_curve());
        assert!(deserialize_g2(&mut &g2_bytes(&point)[..]).is_err());
    }

    fn single_section_zkey(section_id: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ZKEY_MAGIC);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&section_id.to_le_bytes());
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn point_section_must_match_expected_size() {
        let bytes = single_section_zkey(5, &[0u8; 2 * 64]);
        let mut reader = std::io::Cursor::new(bytes);
        let mut binfile = BinFile::new(&mut reader).unwrap();

        assert_eq!(binfile.g1_section(2, 5).unwrap().len(), 2);
        assert!(binfile.g1_section(1, 5).is_err());
        assert!(binfile.g1_section(3, 5).is_err());
        assert!(binfile.g2_section(1, 5).is_ok());
        assert!(binfile.g2_section(2, 5).is_err());
    }
}
