//! Reader for snarkjs `.wtns` witness files
//! (<https://github.com/iden3/snarkjs/blob/master/src/wtns_utils.js>).

use anyhow::{Context, Result, bail, ensure};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let end = at.checked_add(4).context("offset overflow")?;
    Ok(u32::from_le_bytes(
        bytes
            .get(at..end)
            .context("truncated .wtns file")?
            .try_into()?,
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    let end = at.checked_add(8).context("offset overflow")?;
    Ok(u64::from_le_bytes(
        bytes
            .get(at..end)
            .context("truncated .wtns file")?
            .try_into()?,
    ))
}

/// Parses a `.wtns` file of the BN254 scalar field into the witness, wire 0
/// first.
pub fn parse_wtns(bytes: &[u8]) -> Result<Vec<Fr>> {
    ensure!(bytes.get(..4) == Some(b"wtns"), "not a .wtns file");
    let sections = u32_at(bytes, 8)?;
    let mut header = None;
    let mut data = None;
    let mut at = 12usize;
    for _ in 0..sections {
        let kind = u32_at(bytes, at)?;
        let size = usize::try_from(u64_at(bytes, at + 4)?)?;
        let start = at.checked_add(12).context("offset overflow")?;
        let end = start.checked_add(size).context("section overflow")?;
        let body = bytes.get(start..end).context("truncated .wtns section")?;
        match kind {
            1 => header = Some(body),
            2 => data = Some(body),
            _ => {}
        }
        at = end;
    }
    let header = header.context(".wtns has no header section")?;
    let data = data.context(".wtns has no data section")?;
    let n8 = usize::try_from(u32_at(header, 0)?)?;
    ensure!(n8 == 32, "unexpected field size {n8} in .wtns");
    let prime_end = 4usize.checked_add(n8).context("header overflow")?;
    let prime = header.get(4..prime_end).context("truncated .wtns header")?;
    if prime != Fr::MODULUS.to_bytes_le().as_slice() {
        bail!(".wtns is not over the BN254 scalar field");
    }
    let count = usize::try_from(u32_at(header, prime_end)?)?;
    ensure!(
        data.len() == count.checked_mul(n8).context("size overflow")?,
        "bad .wtns data size"
    );
    Ok(data
        .chunks_exact(n8)
        .map(Fr::from_le_bytes_mod_order)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wtns(values: &[Fr]) -> Vec<u8> {
        let prime = Fr::MODULUS.to_bytes_le();
        let mut header = Vec::new();
        header.extend_from_slice(&32u32.to_le_bytes());
        header.extend_from_slice(&prime);
        header.extend_from_slice(&u32::try_from(values.len()).unwrap().to_le_bytes());
        let mut data = Vec::new();
        for v in values {
            data.extend_from_slice(&v.into_bigint().to_bytes_le());
        }
        let mut out = b"wtns".to_vec();
        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        for (kind, body) in [(1u32, header), (2u32, data)] {
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&u64::try_from(body.len()).unwrap().to_le_bytes());
            out.extend_from_slice(&body);
        }
        out
    }

    #[test]
    fn parses_what_snarkjs_writes() {
        let values = [Fr::from(1u8), Fr::from(7u8), -Fr::from(3u8)];
        assert_eq!(parse_wtns(&wtns(&values)).unwrap(), values);
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        assert!(parse_wtns(b"nope").is_err());
        let good = wtns(&[Fr::from(1u8)]);
        assert!(parse_wtns(&good[..good.len() - 1]).is_err());
    }
}
