//! Build and key manifests.
//!
//! The build manifest records what `compile` produced and from which sources.
//! The key manifest is committed next to the key material and binds each key
//! pair to the exact R1CS its trusted setup consumed, so that editing a circuit
//! without rotating the keys fails a check instead of failing after a deploy.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

pub const SCHEMA: u32 = 1;

/// File name of the build manifest inside the artifact directory.
pub const BUILD_MANIFEST: &str = "manifest.json";

/// File name of the key manifest inside the key directory.
pub const KEY_MANIFEST: &str = "keys.manifest.json";

/// sha256 and length of one file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDigest {
    pub sha256: String,
    pub len: u64,
}

impl FileDigest {
    pub fn of(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        Ok(Self {
            sha256: sha256_hex(&bytes),
            len: u64::try_from(bytes.len()).expect("file length fits u64"),
        })
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Toolchain {
    /// Circom compiler tag this builder links against.
    pub circom: String,
    /// Revision from `circuits/circomlib.lock`.
    pub circomlib: String,
    pub prime: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitEntry {
    pub r1cs: FileDigest,
    pub wasm: FileDigest,
    /// `.circom` sources reachable from this entry point, relative to
    /// `circuits/`. Vendored circomlib is excluded: the builder patches it in
    /// place, and `toolchain.circomlib` already pins it.
    pub sources: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildManifest {
    pub schema: u32,
    pub toolchain: Toolchain,
    pub circuits: BTreeMap<String, CircuitEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    /// sha256 of the R1CS the trusted setup consumed. A circuit whose current
    /// R1CS hashes differently has outgrown these keys.
    pub r1cs_sha256: String,
    /// How the key material was produced, e.g. `local` or `ceremony`.
    pub provenance: String,
    /// Key and graph files, keyed by file name within the key directory.
    pub files: BTreeMap<String, FileDigest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyManifest {
    pub schema: u32,
    pub circuits: BTreeMap<String, KeyEntry>,
}

impl KeyManifest {
    pub fn empty() -> Self {
        Self {
            schema: SCHEMA,
            circuits: BTreeMap::new(),
        }
    }
}

/// Lets [`load`] reject a manifest this build cannot interpret.
pub trait Versioned {
    fn schema(&self) -> u32;
}

impl Versioned for BuildManifest {
    fn schema(&self) -> u32 {
        self.schema
    }
}

impl Versioned for KeyManifest {
    fn schema(&self) -> u32 {
        self.schema
    }
}

pub fn load<T: for<'de> Deserialize<'de> + Versioned>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: T =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    anyhow::ensure!(
        value.schema() == SCHEMA,
        "{} has schema {}, this build understands {SCHEMA}",
        path.display(),
        value.schema()
    );
    Ok(value)
}

/// Written atomically, like the artifacts it describes: a half-written manifest
/// would make the build it documents unreadable.
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut text = serde_json::to_string_pretty(value).context("serialize manifest")?;
    text.push('\n');
    crate::paths::write_atomic(path, text.as_bytes())
}
