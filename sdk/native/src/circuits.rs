//! Embedded circuit lockfile and optional GitHub-release download.

use std::collections::BTreeMap;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Embedded circuit lockfile (crate-local `circuits.json`).
pub const CIRCUITS_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/circuits.json"));

/// Kind of circuit artifact named in [`CircuitHashes`] and on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactKind {
    R1cs,
    Graph,
    ProvingKey,
}

impl ArtifactKind {
    pub const ALL: [Self; 3] = [Self::R1cs, Self::Graph, Self::ProvingKey];

    pub fn as_extension(self) -> &'static str {
        match self {
            Self::R1cs => ".r1cs",
            Self::Graph => ".graph.bin",
            Self::ProvingKey => "_proving_key.bin",
        }
    }
}

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

impl CircuitHashes {
    pub fn expected_hash(&self, kind: ArtifactKind) -> &str {
        match kind {
            ArtifactKind::R1cs => self.r1cs.as_str(),
            ArtifactKind::Graph => self.graph.as_str(),
            ArtifactKind::ProvingKey => self.proving_key.as_str(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CircuitLockfile {
    pub version: String,
    pub meta: CircuitMeta,
    #[serde(flatten)]
    pub circuits: BTreeMap<String, CircuitHashes>,
}

impl CircuitLockfile {
    #[cfg(not(target_arch = "wasm32"))]
    pub fn release_url(&self) -> String {
        format!(
            "https://github.com/{}/releases/download/circuits-v{}/circuits.tar.gz",
            self.meta.repository, self.version
        )
    }
}

pub fn circuit_lock() -> Result<CircuitLockfile, Error> {
    serde_json::from_str(CIRCUITS_JSON)
        .map_err(|e| Error::other(format!("parse embedded circuits.json: {e}")))
}

/// On-disk / fetch filename for a circuit artifact.
pub fn artifact_file_name(stem: &str, kind: ArtifactKind) -> String {
    format!("{stem}{}", kind.as_extension())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn decode_sha256_hex(hex_str: &str) -> Result<[u8; 32], Error> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| Error::other(format!("invalid sha256 hex {hex_str}: {e}")))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| Error::other(format!("sha256 hex must be 32 bytes, got {}", v.len())))
}

/// Look up expected hashes for `stem` in the embedded lockfile.
pub fn circuit_hashes(stem: &str) -> Result<CircuitHashes, Error> {
    let lock = circuit_lock()?;
    lock.circuits
        .get(stem)
        .cloned()
        .ok_or_else(|| Error::other(format!("stem {stem} is not in embedded circuits.json")))
}

/// Verify `bytes` against the embedded lockfile entry for `stem` + `kind`.
pub fn verify_artifact_bytes(stem: &str, kind: ArtifactKind, bytes: &[u8]) -> Result<(), Error> {
    let hashes = circuit_hashes(stem)?;
    let want = hashes.expected_hash(kind);
    let got = sha256_hex(bytes);
    if got != want {
        return Err(Error::other(format!(
            "hash mismatch for {}: want {want} got {got}",
            artifact_file_name(stem, kind)
        )));
    }
    Ok(())
}

/// Expected SHA256 digest for `stem` + `kind`, decoded from the lockfile hex
/// string.
pub fn artifact_sha256_bytes(stem: &str, kind: ArtifactKind) -> Result<[u8; 32], Error> {
    let hashes = circuit_hashes(stem)?;
    decode_sha256_hex(hashes.expected_hash(kind))
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

    use super::{
        ArtifactKind, CircuitLockfile, Error, artifact_file_name, circuit_lock,
        verify_artifact_bytes,
    };
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
            read_artifacts(&self.dir, stem)
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
                .all(|(stem, _hashes)| files_ok(&self.dir, stem))
        }
    }

    fn files_ok(dir: &Path, stem: &str) -> bool {
        ArtifactKind::ALL.iter().all(|&kind| {
            let Ok(bytes) = fs::read(dir.join(artifact_file_name(stem, kind))) else {
                return false;
            };
            verify_artifact_bytes(stem, kind, &bytes).is_ok()
        })
    }

    fn read_artifacts(dir: &Path, stem: &str) -> Result<ProverArtifacts, Error> {
        let read = |kind: ArtifactKind| -> Result<Vec<u8>, Error> {
            let path = dir.join(artifact_file_name(stem, kind));
            let bytes = fs::read(&path)
                .map_err(|e| Error::other(format!("read {}: {e}", path.display())))?;
            verify_artifact_bytes(stem, kind, &bytes)?;
            Ok(bytes)
        };
        Ok(ProverArtifacts {
            proving_key: read(ArtifactKind::ProvingKey)?,
            circuit_graph: read(ArtifactKind::Graph)?,
            circuit_r1cs: read(ArtifactKind::R1cs)?,
        })
    }

    fn allowed_names(lock: &CircuitLockfile) -> HashSet<String> {
        let mut names = HashSet::from(["circuits.json".to_string()]);
        for stem in lock.circuits.keys() {
            for kind in ArtifactKind::ALL {
                names.insert(artifact_file_name(stem, kind));
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

    #[test]
    fn artifact_kind_extensions() {
        assert_eq!(ArtifactKind::R1cs.as_extension(), ".r1cs");
        assert_eq!(ArtifactKind::Graph.as_extension(), ".graph.bin");
        assert_eq!(ArtifactKind::ProvingKey.as_extension(), "_proving_key.bin");
    }

    #[test]
    fn artifact_file_names_match_store_layout() {
        assert_eq!(
            artifact_file_name("policy_tx_2_2", ArtifactKind::ProvingKey),
            "policy_tx_2_2_proving_key.bin"
        );
        assert_eq!(
            artifact_file_name("policy_tx_2_2_gvk_V", ArtifactKind::Graph),
            "policy_tx_2_2_gvk_V.graph.bin"
        );
    }
}
