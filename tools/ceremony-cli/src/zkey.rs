// Vendored from arkworks-rs/circom-compat (MIT OR Apache-2.0), commit 09e92d4:
//   https://github.com/arkworks-rs/circom-compat/blob/09e92d4c5887cec9ea558dc7e775a8ab3b02aafc/src/zkey.rs
//
// Local changes: only the proving key is read (the constraint matrices are
// dropped), every section must be consumed exactly, unsupported versions,
// duplicated sections, malformed headers, missing sections, non-canonical
// field elements, invalid curve points, identity verifying key points and a
// delta equal to gamma return errors instead of panicking or being accepted,
// and the upstream test module (which needs the upstream test vectors and the
// wasmer witness calculator) is replaced.
#![allow(clippy::arithmetic_side_effects)]

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
use ark_serialize::{CanonicalDeserialize, SerializationError, Valid};
use byteorder::{LittleEndian, ReadBytesExt};
use num_traits::Zero;
use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom, Take},
};

type IoResult<T> = Result<T, SerializationError>;

const ZKEY_MAGIC: &[u8; 4] = b"zkey";
const ZKEY_VERSION: u32 = 1;
const PROTOCOL_GROTH16: u32 = 1;

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
    sections: HashMap<u32, Section>,
    reader: &'a mut R,
}

impl<'a, R: Read + Seek> BinFile<'a, R> {
    fn new(reader: &'a mut R) -> IoResult<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != ZKEY_MAGIC {
            return Err(SerializationError::InvalidData);
        }

        if reader.read_u32::<LittleEndian>()? != ZKEY_VERSION {
            return Err(SerializationError::InvalidData);
        }

        let num_sections = reader.read_u32::<LittleEndian>()?;

        let mut sections = HashMap::new();
        for _ in 0..num_sections {
            let section_id = reader.read_u32::<LittleEndian>()?;
            let section_length = reader.read_u64::<LittleEndian>()?;

            let section = Section {
                position: reader.stream_position()?,
                size: section_length,
            };
            if sections.insert(section_id, section).is_some() {
                return Err(SerializationError::InvalidData);
            }

            let skip =
                i64::try_from(section_length).map_err(|_| SerializationError::InvalidData)?;
            reader.seek(SeekFrom::Current(skip))?;
        }

        Ok(Self { sections, reader })
    }

    fn check_protocol(&mut self) -> IoResult<()> {
        let protocol = self.read_section(1, |r| Ok(r.read_u32::<LittleEndian>()?))?;
        if protocol != PROTOCOL_GROTH16 {
            return Err(SerializationError::InvalidData);
        }
        Ok(())
    }

    fn proving_key(&mut self) -> IoResult<ProvingKey<Bn254>> {
        let header = self.groth_header()?;
        let ic = self.ic(header.n_public)?;
        // An identity IC point drops its public input from the verification
        // equation, so the verifier would accept any value for it.
        if ic.iter().any(|p| *p == G1Affine::identity()) {
            return Err(SerializationError::InvalidData);
        }

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
            .cloned()
            .ok_or(SerializationError::InvalidData)
    }

    /// Runs `read` over section `id`, bounded to the section's length, and
    /// fails unless it consumes the section exactly.
    fn read_section<T>(
        &mut self,
        id: u32,
        read: impl FnOnce(&mut Take<&mut R>) -> IoResult<T>,
    ) -> IoResult<T> {
        let section = self.get_section(id)?;
        self.reader.seek(SeekFrom::Start(section.position))?;
        let mut reader = (&mut *self.reader).take(section.size);
        let value = read(&mut reader)?;
        if reader.limit() != 0 {
            return Err(SerializationError::InvalidData);
        }
        Ok(value)
    }

    fn groth_header(&mut self) -> IoResult<HeaderGroth> {
        self.read_section(2, |r| HeaderGroth::read(r))
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

    fn g1_section(&mut self, num: usize, section_id: u32) -> IoResult<Vec<G1Affine>> {
        self.read_section(section_id, |r| deserialize_g1_vec(r, num))
    }

    fn g2_section(&mut self, num: usize, section_id: u32) -> IoResult<Vec<G2Affine>> {
        self.read_section(section_id, |r| deserialize_g2_vec(r, num))
    }
}

#[derive(Clone, Debug)]
struct ZVerifyingKey {
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

        // No valid setup has identity points here. `zkey new` emits
        // delta == gamma before any contribution, which lets anyone forge a
        // proof for any public input by cancelling C against the IC term.
        if [alpha_g1, beta_g1, delta_g1].contains(&G1Affine::identity())
            || [beta_g2, gamma_g2, delta_g2].contains(&G2Affine::identity())
            || delta_g2 == gamma_g2
        {
            return Err(SerializationError::InvalidData);
        }

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
    n_vars: usize,
    n_public: usize,
    domain_size: u32,
    verifying_key: ZVerifyingKey,
}

impl HeaderGroth {
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

        let verifying_key = ZVerifyingKey::new(&mut reader)?;

        Ok(Self {
            n_vars,
            n_public,
            domain_size,
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

fn deserialize_field2<R: Read>(reader: &mut R) -> IoResult<Fq2> {
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
    point.check()?;
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
    point.check()?;
    Ok(point)
}

fn deserialize_g1_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G1Affine>> {
    (0..n_vars).map(|_| deserialize_g1(reader)).collect()
}

fn deserialize_g2_vec<R: Read>(reader: &mut R, n_vars: usize) -> IoResult<Vec<G2Affine>> {
    (0..n_vars).map(|_| deserialize_g2(reader)).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
pub(crate) mod tests {
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

    fn zkey_file(sections: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ZKEY_MAGIC);
        out.extend_from_slice(&ZKEY_VERSION.to_le_bytes());
        out.extend_from_slice(&u32::try_from(sections.len()).unwrap().to_le_bytes());
        for (id, body) in sections {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&u64::try_from(body.len()).unwrap().to_le_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    fn g1_generator() -> G1Affine {
        G1Affine::new_unchecked(g1::G1_GENERATOR_X, g1::G1_GENERATOR_Y)
    }

    fn g2_generator() -> G2Affine {
        G2Affine::new_unchecked(g2::G2_GENERATOR_X, g2::G2_GENERATOR_Y)
    }

    /// Generator points everywhere, except delta, which is doubled so it
    /// differs from gamma.
    fn valid_header() -> ZVerifyingKey {
        let (g1, g2) = (g1_generator(), g2_generator());
        ZVerifyingKey {
            alpha_g1: g1,
            beta_g1: g1,
            beta_g2: g2,
            gamma_g2: g2,
            delta_g1: (g1 + g1).into(),
            delta_g2: (g2 + g2).into(),
        }
    }

    pub(crate) fn valid_zkey() -> Vec<u8> {
        minimal_zkey(&valid_header(), &g1_generator())
    }

    /// A one-variable, zero-public-input zkey with the given header points and
    /// IC[0]. The proving key queries are all identity.
    fn minimal_zkey(vk: &ZVerifyingKey, ic0: &G1Affine) -> Vec<u8> {
        let g1 = vec![0u8; 64];
        let g2 = vec![0u8; 128];

        let mut header = Vec::new();
        header.extend_from_slice(&32u32.to_le_bytes());
        write_fq(&mut header, Fq::MODULUS);
        header.extend_from_slice(&32u32.to_le_bytes());
        write_fq(&mut header, Fr::MODULUS);
        header.extend_from_slice(&1u32.to_le_bytes()); // n_vars
        header.extend_from_slice(&0u32.to_le_bytes()); // n_public
        header.extend_from_slice(&1u32.to_le_bytes()); // domain_size
        header.extend(g1_bytes(&vk.alpha_g1));
        header.extend(g1_bytes(&vk.beta_g1));
        header.extend(g2_bytes(&vk.beta_g2));
        header.extend(g2_bytes(&vk.gamma_g2));
        header.extend(g1_bytes(&vk.delta_g1));
        header.extend(g2_bytes(&vk.delta_g2));

        zkey_file(&[
            (1, PROTOCOL_GROTH16.to_le_bytes().to_vec()),
            (2, header),
            (3, g1_bytes(ic0)),
            (5, g1.clone()),
            (6, g1.clone()),
            (7, g2),
            (8, Vec::new()),
            (9, g1),
        ])
    }

    fn parses(vk: &ZVerifyingKey, ic0: &G1Affine) -> bool {
        read_zkey(&mut std::io::Cursor::new(minimal_zkey(vk, ic0))).is_ok()
    }

    #[test]
    fn read_zkey_accepts_valid_key() {
        let pk = read_zkey(&mut std::io::Cursor::new(valid_zkey())).unwrap();
        assert_eq!(pk.vk.gamma_abc_g1, vec![g1_generator()]);
        assert_eq!(pk.delta_g1, valid_header().delta_g1);
    }

    #[test]
    fn read_zkey_rejects_identity_ic() {
        assert!(!parses(&valid_header(), &G1Affine::identity()));
    }

    #[test]
    fn read_zkey_rejects_identity_header_points() {
        let edits: [fn(&mut ZVerifyingKey); 6] = [
            |vk| vk.alpha_g1 = G1Affine::identity(),
            |vk| vk.beta_g1 = G1Affine::identity(),
            |vk| vk.beta_g2 = G2Affine::identity(),
            |vk| vk.gamma_g2 = G2Affine::identity(),
            |vk| vk.delta_g1 = G1Affine::identity(),
            |vk| vk.delta_g2 = G2Affine::identity(),
        ];
        for edit in edits {
            let mut vk = valid_header();
            edit(&mut vk);
            assert!(!parses(&vk, &g1_generator()));
        }
    }

    #[test]
    fn read_zkey_rejects_uncontributed_key() {
        let vk = ZVerifyingKey {
            delta_g1: g1_generator(),
            delta_g2: g2_generator(),
            ..valid_header()
        };
        assert!(!parses(&vk, &g1_generator()));
    }

    #[test]
    fn section_must_be_consumed_exactly() {
        let bytes = zkey_file(&[(5, vec![0u8; 2 * 64])]);
        let mut reader = std::io::Cursor::new(bytes);
        let mut binfile = BinFile::new(&mut reader).unwrap();

        assert_eq!(binfile.g1_section(2, 5).unwrap().len(), 2);
        assert!(binfile.g1_section(1, 5).is_err());
        assert!(binfile.g1_section(3, 5).is_err());
        assert!(binfile.g2_section(1, 5).is_ok());
        assert!(binfile.g2_section(2, 5).is_err());
    }

    #[test]
    fn binfile_rejects_unsupported_version() {
        let mut bytes = zkey_file(&[]);
        assert!(BinFile::new(&mut std::io::Cursor::new(bytes.clone())).is_ok());
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(BinFile::new(&mut std::io::Cursor::new(bytes)).is_err());
    }

    #[test]
    fn binfile_rejects_duplicated_section() {
        let unique = zkey_file(&[(3, Vec::new()), (4, Vec::new())]);
        assert!(BinFile::new(&mut std::io::Cursor::new(unique)).is_ok());
        let duplicated = zkey_file(&[(3, Vec::new()), (3, Vec::new())]);
        assert!(BinFile::new(&mut std::io::Cursor::new(duplicated)).is_err());
    }
}
