//! Nullifier cursor persisted between keeper rounds.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

/// Nullifiers discovered from pool events, and where event paging stopped.
///
/// Nullifier ledger entries cannot be derived from the manifest, so the keeper
/// accumulates them from `NewNullifierEvent` and keeps them here. Each
/// nullifier is a 32-byte big-endian integer in lowercase hexadecimal, without
/// a `0x` prefix.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Event cursor from the last page the keeper read, absent before the
    /// first round.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Nullifiers seen so far, keyed by pool contract id.
    ///
    /// A set rather than a list: this is the one value in the file that grows
    /// without bound, and every round re-reads the pages it has already seen
    /// when a cursor is refused.
    #[serde(default)]
    pub nullifiers: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    /// Reads the state file, returning an empty state when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw)
                .with_context(|| format!("parse state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read state file {}", path.display())),
        }
    }

    /// Writes the state through a temporary file and a rename.
    ///
    /// A round that dies mid-write leaves either the previous state or the new
    /// one, never a truncated file that the next round would fail to parse.
    ///
    /// # Errors
    ///
    /// Returns an error if the temporary file cannot be written or renamed.
    pub fn store(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        let encoded = serde_json::to_string_pretty(self).context("encode keeper state")?;
        fs::write(&tmp, encoded).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("rename {}", tmp.display()))
    }

    /// Records nullifiers against a pool.
    pub fn extend_pool(&mut self, pool_id: &str, nullifiers: impl IntoIterator<Item = String>) {
        self.nullifiers
            .entry(pool_id.to_owned())
            .or_default()
            .extend(nullifiers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> State {
        let mut state = State {
            cursor: Some("0004-000".into()),
            nullifiers: BTreeMap::new(),
        };
        state.extend_pool("CPOOL", ["aa".to_string(), "bb".to_string()]);
        state
    }

    #[test]
    fn the_state_file_round_trips_and_survives_a_truncated_temporary_file() {
        let dir = std::env::temp_dir().join(format!("ttl-keeper-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("keeper-state.json");

        sample().store(&path).expect("store");
        assert_eq!(State::load(&path).expect("load"), sample());

        // A round killed mid-write leaves the temporary file behind; the state
        // file itself is whole because the rename is atomic.
        std::fs::write(path.with_extension("json.tmp"), "{\"cursor\":").expect("truncated tmp");
        assert_eq!(State::load(&path).expect("load after crash"), sample());

        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn a_missing_state_file_loads_as_empty() {
        let path =
            std::env::temp_dir().join(format!("ttl-keeper-absent-{}.json", std::process::id()));
        assert_eq!(State::load(&path).expect("load"), State::default());
    }

    #[test]
    fn appending_a_known_nullifier_does_not_duplicate_it() {
        let mut state = sample();
        state.extend_pool("CPOOL", ["bb".to_string(), "cc".to_string()]);
        assert_eq!(
            state.nullifiers["CPOOL"],
            BTreeSet::from(["aa".to_string(), "bb".to_string(), "cc".to_string()])
        );
    }
}
