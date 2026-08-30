//! Embedded circuit lockfile and optional GitHub-release download.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::Error;

/// Embedded circuit lockfile (crate-local `circuits.json`).
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

#[cfg(not(target_arch = "wasm32"))]
mod store {
    use std::{
        collections::HashSet,
        fs,
        io::Cursor,
        path::{Component, Path, PathBuf},
    };

    use flate2::read::GzDecoder;
    use sha2::{Digest, Sha256};
    use tar::Archive;

    use super::{CircuitHashes, CircuitLockfile, Error, circuit_lock};
    use crate::types::{
        CircuitStem, GvkMode, ProverArtifacts, SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT, SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    };

    const DISCLOSURE_STEMS: [&str; 4] = [
        SELECTIVE_DISCLOSURE_1_CIRCUIT,
        SELECTIVE_DISCLOSURE_2_CIRCUIT,
        SELECTIVE_DISCLOSURE_3_CIRCUIT,
        SELECTIVE_DISCLOSURE_4_CIRCUIT,
    ];

    const KINDS: [&str; 3] = ["r1cs", "graph.bin", "proving_key.bin"];

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
            let hashes = lock.circuits.get(stem).ok_or_else(|| {
                Error::other(format!("stem {stem} is not in embedded circuits.json"))
            })?;
            read_artifacts(&self.dir, stem, hashes)
        }

        pub fn transact_artifacts(&self) -> Result<Vec<(CircuitStem, ProverArtifacts)>, Error> {
            CircuitStem::all_transact_stems()
                .into_iter()
                .filter(|stem| stem.gvk_mode == GvkMode::Off)
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
                .all(|(stem, hashes)| files_ok(&self.dir, stem, hashes))
        }
    }

    fn file_name(stem: &str, kind: &str) -> String {
        match kind {
            "r1cs" => format!("{stem}.r1cs"),
            "graph.bin" => format!("{stem}.graph.bin"),
            "proving_key.bin" => format!("{stem}_proving_key.bin"),
            _ => format!("{stem}.{kind}"),
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn files_ok(dir: &Path, stem: &str, hashes: &CircuitHashes) -> bool {
        KINDS.iter().all(|kind| {
            let Ok(bytes) = fs::read(dir.join(file_name(stem, kind))) else {
                return false;
            };
            let want = match *kind {
                "r1cs" => hashes.r1cs.as_str(),
                "graph.bin" => hashes.graph.as_str(),
                "proving_key.bin" => hashes.proving_key.as_str(),
                _ => return false,
            };
            sha256_hex(&bytes) == want
        })
    }

    fn read_artifacts(
        dir: &Path,
        stem: &str,
        hashes: &CircuitHashes,
    ) -> Result<ProverArtifacts, Error> {
        let read = |kind: &str, want: &str| -> Result<Vec<u8>, Error> {
            let path = dir.join(file_name(stem, kind));
            let bytes = fs::read(&path)
                .map_err(|e| Error::other(format!("read {}: {e}", path.display())))?;
            let got = sha256_hex(&bytes);
            if got != want {
                return Err(Error::other(format!(
                    "hash mismatch {}: want {want} got {got}",
                    path.display()
                )));
            }
            Ok(bytes)
        };
        Ok(ProverArtifacts {
            proving_key: read("proving_key.bin", &hashes.proving_key)?,
            circuit_graph: read("graph.bin", &hashes.graph)?,
            circuit_r1cs: read("r1cs", &hashes.r1cs)?,
        })
    }

    fn allowed_names(lock: &CircuitLockfile) -> HashSet<String> {
        let mut names = HashSet::from(["circuits.json".to_string()]);
        for stem in lock.circuits.keys() {
            for kind in KINDS {
                names.insert(file_name(stem, kind));
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
        CircuitStem, GvkMode, SELECTIVE_DISCLOSURE_1_CIRCUIT, SELECTIVE_DISCLOSURE_2_CIRCUIT,
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
            if stem.gvk_mode != GvkMode::Off {
                continue;
            }
            let stem_str = stem.to_string();
            assert!(lock.circuits.contains_key(&stem_str), "missing {stem_str}");
        }
        for stem in DISCLOSURE_STEMS {
            assert!(lock.circuits.contains_key(stem), "missing {stem}");
        }
    }
}
