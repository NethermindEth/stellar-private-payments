//! Embedded circuit lockfile and optional GitHub-release download.

use std::collections::BTreeMap;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::Error;

pub const CIRCUITS_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/circuits.json"));

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitMeta {
    pub repository: String,
    pub commit: String,
    pub circom: String,
    pub circomlib: String,
    #[serde(rename = "circom-witness-rs")]
    pub circom_witness_rs: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitHashes {
    pub setup: String,
    pub r1cs: String,
    #[serde(rename = "graph.bin")]
    pub graph: String,
    #[serde(rename = "proving_key.bin")]
    pub proving_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitLockfile {
    pub version: String,
    pub meta: CircuitMeta,
    #[serde(flatten)]
    pub circuits: BTreeMap<String, CircuitHashes>,
}

impl CircuitLockfile {
    pub const ARTIFACT_KINDS: [&'static str; 3] = ["r1cs", "graph.bin", "proving_key.bin"];

    pub fn release_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/download/circuits-v{}/circuits.tar.gz",
            self.meta.repository, self.version
        )
    }

    pub fn artifact_file_name(stem: &str, kind: &str) -> String {
        match kind {
            "r1cs" => format!("{stem}.r1cs"),
            "graph.bin" => format!("{stem}.graph.bin"),
            "proving_key.bin" => format!("{stem}_proving_key.bin"),
            _ => format!("{stem}.{kind}"),
        }
    }

    pub fn verify_artifact(&self, stem: &str, kind: &str, bytes: &[u8]) -> Result<(), Error> {
        let hashes = self.entry(stem)?;
        let want = Self::expected_hash_hex(hashes, kind)?;
        let got = Self::sha256_hex(bytes);
        if got != want {
            return Err(Error::other(format!(
                "hash mismatch {stem}/{kind}: want {want} got {got}"
            )));
        }
        Ok(())
    }

    pub fn artifact_sha256(&self, stem: &str, kind: &str) -> Result<[u8; 32], Error> {
        let hashes = self.entry(stem)?;
        let hex = Self::expected_hash_hex(hashes, kind)?;
        let bytes = hex::decode(hex)
            .map_err(|e| Error::other(format!("invalid hash hex for {stem}/{kind}: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::other(format!(
                "expected 32-byte hash for {stem}/{kind}, got {} hex chars",
                hex.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn entry(&self, stem: &str) -> Result<&CircuitHashes, Error> {
        self.circuits
            .get(stem)
            .ok_or_else(|| Error::other(format!("stem {stem} is not in embedded circuits.json")))
    }

    fn expected_hash_hex<'a>(hashes: &'a CircuitHashes, kind: &str) -> Result<&'a str, Error> {
        match kind {
            "r1cs" => Ok(hashes.r1cs.as_str()),
            "graph.bin" => Ok(hashes.graph.as_str()),
            "proving_key.bin" => Ok(hashes.proving_key.as_str()),
            other => Err(Error::other(format!("unknown artifact kind: {other}"))),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }
}

pub fn circuit_lock() -> Result<CircuitLockfile, Error> {
    serde_json::from_str(CIRCUITS_JSON)
        .map_err(|e| Error::other(format!("parse embedded circuits.json: {e}")))
}

#[cfg(not(target_arch = "wasm32"))]
mod store {
    use std::{
        collections::HashSet,
        fs,
        io::Cursor,
        path::{Component, Path, PathBuf},
    };

    use flate2::read::GzDecoder;
    use tar::Archive;

    use super::{CircuitLockfile, Error, circuit_lock};
    use crate::types::{
        CircuitStem, ProverArtifacts, SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT, SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    };

    const DISCLOSURE_STEMS: [&str; 4] = [
        SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    ];

    pub struct CircuitStore {
        dir: PathBuf,
    }

    impl CircuitStore {
        pub fn open(dir: impl Into<PathBuf>) -> Self {
            Self { dir: dir.into() }
        }

        pub fn dir(&self) -> &Path {
            &self.dir
        }

        pub async fn ensure(&self) -> Result<(), Error> {
            let lock = circuit_lock()?;
            fs::create_dir_all(&self.dir).map_err(|e| Error::other(e.to_string()))?;
            if self.ready(&lock) {
                return Ok(());
            }

            let url = lock.release_url();
            let bytes = reqwest::Client::new()
                .get(&url)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| Error::other(format!("download {url}: {e}")))?
                .bytes()
                .await
                .map_err(|e| Error::other(format!("download {url}: {e}")))?;

            unpack_tar_gz(&bytes, &self.dir, &allowed_names(&lock))?;
            if self.ready(&lock) {
                Ok(())
            } else {
                Err(Error::other(
                    "downloaded circuit artifacts do not match embedded circuits.json",
                ))
            }
        }

        pub fn ensure_blocking(&self) -> Result<(), Error> {
            crate::blocking::runtime::block_on(self.ensure())
        }

        pub fn artifacts(&self, stem: &str) -> Result<ProverArtifacts, Error> {
            let lock = circuit_lock()?;
            let _ = lock.entry(stem)?;
            read_artifacts(&self.dir, stem, &lock)
        }

        pub fn transact_artifacts(&self) -> Result<Vec<(CircuitStem, ProverArtifacts)>, Error> {
            CircuitStem::all_transact_stems()
                .into_iter()
                .map(|stem| {
                    self.artifacts(&stem.to_string())
                        .map(|artifacts| (stem, artifacts))
                })
                .collect()
        }

        pub fn disclosure_artifacts(&self) -> Result<Vec<(&'static str, ProverArtifacts)>, Error> {
            DISCLOSURE_STEMS
                .iter()
                .copied()
                .map(|stem| self.artifacts(stem).map(|artifacts| (stem, artifacts)))
                .collect()
        }

        fn ready(&self, lock: &CircuitLockfile) -> bool {
            lock.circuits
                .iter()
                .all(|(stem, _)| files_ok(&self.dir, stem, lock))
        }
    }

    fn files_ok(dir: &Path, stem: &str, lock: &CircuitLockfile) -> bool {
        CircuitLockfile::ARTIFACT_KINDS.iter().all(|&kind| {
            let path = dir.join(CircuitLockfile::artifact_file_name(stem, kind));
            let Ok(bytes) = fs::read(&path) else {
                return false;
            };
            lock.verify_artifact(stem, kind, &bytes).is_ok()
        })
    }

    fn read_artifacts(
        dir: &Path,
        stem: &str,
        lock: &CircuitLockfile,
    ) -> Result<ProverArtifacts, Error> {
        let read = |kind: &str| -> Result<Vec<u8>, Error> {
            let path = dir.join(CircuitLockfile::artifact_file_name(stem, kind));
            let bytes = fs::read(&path)
                .map_err(|e| Error::other(format!("read {}: {e}", path.display())))?;
            lock.verify_artifact(stem, kind, &bytes)
                .map_err(|e| Error::other(format!("{}: {e}", path.display())))?;
            Ok(bytes)
        };
        Ok(ProverArtifacts {
            proving_key: read("proving_key.bin")?,
            circuit_graph: read("graph.bin")?,
            circuit_r1cs: read("r1cs")?,
        })
    }

    fn allowed_names(lock: &CircuitLockfile) -> HashSet<String> {
        let mut names = HashSet::from(["circuits.json".to_string()]);
        for stem in lock.circuits.keys() {
            for kind in CircuitLockfile::ARTIFACT_KINDS {
                names.insert(CircuitLockfile::artifact_file_name(stem, kind));
            }
        }
        names
    }

    fn tar_basename(path: &Path) -> Option<&str> {
        let mut name = None;
        for component in path.components() {
            match component {
                Component::CurDir => {}
                Component::Normal(s) if name.is_none() => name = s.to_str(),
                _ => return None,
            }
        }
        name
    }

    fn unpack_tar_gz(bytes: &[u8], dest: &Path, allowed: &HashSet<String>) -> Result<(), Error> {
        let mut archive = Archive::new(GzDecoder::new(Cursor::new(bytes)));
        let entries = archive
            .entries()
            .map_err(|e| Error::other(format!("read circuits.tar.gz: {e}")))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| Error::other(format!("circuits.tar.gz: {e}")))?;
            let name = {
                let path = entry
                    .path()
                    .map_err(|e| Error::other(format!("circuits.tar.gz: {e}")))?;
                tar_basename(&path).map(str::to_owned)
            };
            let Some(name) = name else {
                continue;
            };
            if !allowed.contains(&name) {
                continue;
            }
            entry
                .unpack(dest.join(&name))
                .map_err(|e| Error::other(format!("extract {name}: {e}")))?;
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use store::CircuitStore;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        CircuitStem, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT, SELECTIVE_DISCLOSURE_4_CIRCUIT,
    };

    const DISCLOSURE_STEMS: [&str; 4] = [
        SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    ];

    #[test]
    fn lockfile_covers_transact_and_disclosure() {
        let lock = circuit_lock().expect("parse embedded circuits.json");
        assert!(!lock.version.is_empty());
        for stem in CircuitStem::all_transact_stems() {
            let stem_str = stem.to_string();
            assert!(lock.circuits.contains_key(&stem_str), "missing {stem_str}");
        }
        for stem in DISCLOSURE_STEMS {
            assert!(lock.circuits.contains_key(stem), "missing {stem}");
        }
    }
}
