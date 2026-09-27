//! Serialize CLI database use before immutable preflight or key-record updates.
//! Lock the directory inode, which remains stable across database/key renames.
use anyhow::{Context, Result};
use std::{fs::File, path::Path};

pub fn acquire(directory: &Path) -> Result<File> {
    std::fs::create_dir_all(directory)?;
    let owner = File::open(directory)?;
    owner.try_lock().with_context(|| format!(
        "cannot exclusively own local storage at {}; close other spp commands using this directory", directory.display()
    ))?;
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_lock_blocks_another_open_and_releases_on_drop() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("spp-owner-{}", std::process::id()));
        let first = acquire(&dir)?;
        assert!(acquire(&dir).is_err());
        drop(first);
        drop(acquire(&dir)?);
        std::fs::remove_dir(dir)?;
        Ok(())
    }
}
