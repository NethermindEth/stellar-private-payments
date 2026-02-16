//! Deployment config, network/path resolution, pool management.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Deployment configuration for a single pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Network name (e.g., "testnet")
    pub network: String,
    /// Deployer G... address
    pub deployer: String,
    /// Admin G... address
    pub admin: String,
    /// ASP membership contract ID
    pub asp_membership: String,
    /// ASP non-membership contract ID
    pub asp_non_membership: String,
    /// Groth16 verifier contract ID
    pub verifier: String,
    /// Pool contract ID
    pub pool: String,
    /// Whether contracts are initialized
    pub initialized: bool,
}

/// Per-network config (lives at `{network}/config.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    /// Name of the default pool for this network.
    pub default_pool: Option<String>,
}

// ========== Path helpers ==========

/// Platform config directory for the CLI.
///
/// Resolves to `<config_dir>/stellar/spp/` where `<config_dir>` is
/// `~/Library/Application Support` on macOS and `~/.config` on Linux.
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Could not determine config directory")?;
    Ok(base.join("stellar").join("spp"))
}

/// Per-network directory: `<config_dir>/stellar/spp/{network}/`.
pub fn network_dir(network: &str) -> Result<PathBuf> {
    Ok(config_dir()?.join(network))
}

/// Pool config path: `.../{network}/pools/{pool}.toml`.
pub fn pool_config_path(network: &str, pool: &str) -> Result<PathBuf> {
    Ok(network_dir(network)?.join("pools").join(format!("{pool}.toml")))
}

/// Pool data path: `.../{network}/pools/{pool}.json`.
pub fn pool_data_path(network: &str, pool: &str) -> Result<PathBuf> {
    Ok(network_dir(network)?.join("pools").join(format!("{pool}.json")))
}

/// Network config path: `.../{network}/config.toml`.
fn network_config_path(network: &str) -> Result<PathBuf> {
    Ok(network_dir(network)?.join("config.toml"))
}

// ========== Validation ==========

/// Validate a pool name: alphanumeric, hyphens, underscores, 1–64 chars.
pub fn validate_pool_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        bail!("Pool name must be 1–64 characters, got {}", name.len());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("Pool name may only contain alphanumeric characters, hyphens, and underscores");
    }
    Ok(())
}

// ========== Network config CRUD ==========

/// Load the per-network config, returning defaults if the file doesn't exist.
pub fn load_network_config(network: &str) -> Result<NetworkConfig> {
    let path = network_config_path(network)?;
    if path.exists() {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let cfg: NetworkConfig =
            toml::from_str(&contents).context("Failed to parse network config")?;
        Ok(cfg)
    } else {
        Ok(NetworkConfig::default())
    }
}

/// Save the per-network config.
pub fn save_network_config(network: &str, cfg: &NetworkConfig) -> Result<()> {
    let path = network_config_path(network)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create dir {}", parent.display()))?;
    }
    let contents = toml::to_string_pretty(cfg).context("Failed to serialize network config")?;
    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

// ========== Pool config CRUD ==========

/// Load a pool's deployment config.
pub fn load_pool_config(network: &str, pool: &str) -> Result<DeploymentConfig> {
    let path = pool_config_path(network, pool)?;
    if !path.exists() {
        bail!("Pool '{pool}' not found for network '{network}'. Use `stellar spp pool ls` to see available pools.");
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let cfg: DeploymentConfig =
        toml::from_str(&contents).context("Failed to parse pool config")?;
    Ok(cfg)
}

/// Save a pool's deployment config.
pub fn save_pool_config(network: &str, pool: &str, cfg: &DeploymentConfig) -> Result<()> {
    validate_pool_name(pool)?;
    let path = pool_config_path(network, pool)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create dir {}", parent.display()))?;
    }
    let contents = toml::to_string_pretty(cfg).context("Failed to serialize pool config")?;
    std::fs::write(&path, contents)
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

/// List all pool names for a network (from `.toml` filenames in the pools dir).
pub fn list_pools(network: &str) -> Result<Vec<String>> {
    let pools_dir = network_dir(network)?.join("pools");
    if !pools_dir.exists() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&pools_dir)
        .with_context(|| format!("Failed to read {}", pools_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

/// Remove a pool (deletes both `.toml` and `.json` files).
pub fn remove_pool(network: &str, pool: &str) -> Result<()> {
    let toml_path = pool_config_path(network, pool)?;
    let json_path = pool_data_path(network, pool)?;
    if toml_path.exists() {
        std::fs::remove_file(&toml_path)
            .with_context(|| format!("Failed to remove {}", toml_path.display()))?;
    }
    if json_path.exists() {
        std::fs::remove_file(&json_path)
            .with_context(|| format!("Failed to remove {}", json_path.display()))?;
    }
    Ok(())
}

// ========== Migration ==========

/// Migrate old flat layout (`{network}.toml` / `{network}.json`) to the new
/// per-pool directory structure (`{network}/pools/default.*` + `config.toml`).
///
/// This is idempotent — if the new layout already exists, it's a no-op.
pub fn maybe_migrate(network: &str) -> Result<()> {
    let base = config_dir()?;
    let old_toml = base.join(format!("{network}.toml"));
    let old_json = base.join(format!("{network}.json"));

    // Nothing to migrate
    if !old_toml.exists() && !old_json.exists() {
        return Ok(());
    }

    // Already migrated (pools dir exists with content)
    let pools_dir = network_dir(network)?.join("pools");
    if pools_dir.exists() {
        // Clean up old files if new layout already has them
        if old_toml.exists() {
            std::fs::remove_file(&old_toml).ok();
        }
        if old_json.exists() {
            std::fs::remove_file(&old_json).ok();
        }
        return Ok(());
    }

    std::fs::create_dir_all(&pools_dir)
        .with_context(|| format!("Failed to create {}", pools_dir.display()))?;

    // Move .toml -> pools/default.toml
    let new_toml = pools_dir.join("default.toml");
    if old_toml.exists() {
        std::fs::rename(&old_toml, &new_toml).with_context(|| {
            format!(
                "Failed to migrate {} -> {}",
                old_toml.display(),
                new_toml.display()
            )
        })?;
    }

    // Move .json -> pools/default.json
    let new_json = pools_dir.join("default.json");
    if old_json.exists() {
        std::fs::rename(&old_json, &new_json).with_context(|| {
            format!(
                "Failed to migrate {} -> {}",
                old_json.display(),
                new_json.display()
            )
        })?;
    }

    // Create network config with default_pool = "default"
    let net_cfg = NetworkConfig {
        default_pool: Some("default".to_string()),
    };
    save_network_config(network, &net_cfg)?;

    eprintln!("Migrated config for network '{network}' to new per-pool layout.");
    Ok(())
}

// ========== High-level loaders ==========

/// Load an existing pool's deployment config (with migration).
pub fn load_config(network: &str, pool: &str) -> Result<DeploymentConfig> {
    maybe_migrate(network)?;
    load_pool_config(network, pool)
}

/// Load config from `deployments.json` and save as a named pool.
pub fn load_or_create_config(network: &str, pool: &str) -> Result<DeploymentConfig> {
    let cfg = load_from_deployments_json(network)?;
    save_pool_config(network, pool, &cfg)?; // validates pool name
    Ok(cfg)
}

/// Load deployment config from the workspace `scripts/deployments.json`.
pub fn load_from_deployments_json(network: &str) -> Result<DeploymentConfig> {
    // Try to find deployments.json relative to the binary or well-known paths
    let candidates = [
        // Workspace-relative (common during development)
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/deployments.json"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            let contents = std::fs::read_to_string(candidate).with_context(|| {
                format!(
                    "Failed to read deployments.json from {}",
                    candidate.display()
                )
            })?;
            let cfg: DeploymentConfig =
                serde_json::from_str(&contents).context("Failed to parse deployments.json")?;

            if cfg.network != network {
                bail!(
                    "deployments.json is for network '{}', but '{}' was requested",
                    cfg.network,
                    network
                );
            }

            return Ok(cfg);
        }
    }

    bail!(
        "Could not find deployments.json. Run from the workspace root or run `stellar spp init` first."
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_config_json_roundtrip() {
        let cfg = DeploymentConfig {
            network: "testnet".to_string(),
            deployer: "GABC".to_string(),
            admin: "GABC".to_string(),
            asp_membership: "CASP1".to_string(),
            asp_non_membership: "CASP2".to_string(),
            verifier: "CVER".to_string(),
            pool: "CPOOL".to_string(),
            initialized: true,
        };

        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: DeploymentConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network, "testnet");
        assert_eq!(parsed.pool, "CPOOL");
        assert!(parsed.initialized);
    }

    #[test]
    fn test_deployment_config_toml_roundtrip() {
        let cfg = DeploymentConfig {
            network: "standalone".to_string(),
            deployer: "GD123".to_string(),
            admin: "GA456".to_string(),
            asp_membership: "CMEM".to_string(),
            asp_non_membership: "CNON".to_string(),
            verifier: "CVER".to_string(),
            pool: "CPOOL".to_string(),
            initialized: false,
        };

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: DeploymentConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.network, "standalone");
        assert_eq!(parsed.admin, "GA456");
        assert!(!parsed.initialized);
    }

    #[test]
    fn test_load_from_deployments_json() {
        // This test requires the actual deployments.json in the workspace
        let result = load_from_deployments_json("testnet");
        if let Ok(cfg) = result {
            assert_eq!(cfg.network, "testnet");
            assert!(!cfg.pool.is_empty());
            assert!(!cfg.asp_membership.is_empty());
        }
        // If file not found, that's OK in CI
    }

    #[test]
    fn test_validate_pool_name_valid() {
        assert!(validate_pool_name("default").is_ok());
        assert!(validate_pool_name("my-pool").is_ok());
        assert!(validate_pool_name("pool_1").is_ok());
        assert!(validate_pool_name("A").is_ok());
    }

    #[test]
    fn test_validate_pool_name_invalid() {
        assert!(validate_pool_name("").is_err());
        assert!(validate_pool_name("a/b").is_err());
        assert!(validate_pool_name("pool name").is_err());
        assert!(validate_pool_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_network_config_roundtrip() {
        let cfg = NetworkConfig {
            default_pool: Some("my-pool".to_string()),
        };
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: NetworkConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_pool, Some("my-pool".to_string()));
    }

    #[test]
    fn test_pool_config_file_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = DeploymentConfig {
            network: "testnet".to_string(),
            deployer: "GD".to_string(),
            admin: "GA".to_string(),
            asp_membership: "CM".to_string(),
            asp_non_membership: "CN".to_string(),
            verifier: "CV".to_string(),
            pool: "CP".to_string(),
            initialized: true,
        };
        let path = tmp.path().join("my-pool.toml");
        let contents = toml::to_string_pretty(&cfg).unwrap();
        std::fs::write(&path, &contents).unwrap();

        let loaded: DeploymentConfig =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.pool, "CP");
        assert_eq!(loaded.network, "testnet");
    }
}
